// language: C++, file: main.cpp, target: Windows 11 x64, MSVC
#include <windows.h>
#include <commdlg.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include "ntldr.hpp"
#include "mapper.hpp"
#include "pe_inspector.hpp"

#pragma comment(lib, "Comdlg32.lib")

namespace {

bool read_file(const std::string& path, std::vector<uint8_t>& bytes) {
    std::ifstream file(std::filesystem::u8path(path), std::ios::binary | std::ios::ate);
    if (!file) return false;
    const auto length = file.tellg();
    if (length <= 0 || length > 1024LL * 1024LL * 1024LL) return false;
    bytes.resize(static_cast<size_t>(length));
    file.seekg(0);
    return static_cast<bool>(file.read(reinterpret_cast<char*>(bytes.data()), length));
}

bool to_wide(const std::string& input, std::wstring& output) {
    if (input.empty()) return false;
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                           static_cast<int>(input.size()), nullptr, 0);
    if (length == 0) return false;
    output.resize(length);
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                               static_cast<int>(input.size()), output.data(), length) == length;
}

bool choose_dll(std::string& path, DWORD& dialog_error) {
    wchar_t selected[MAX_PATH * 16]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetConsoleWindow();
    dialog.lpstrFilter = L"DLL files (*.dll)\0*.dll\0All files (*.*)\0*.*\0\0";
    dialog.lpstrFile = selected;
    dialog.nMaxFile = static_cast<DWORD>(std::size(selected));
    dialog.lpstrTitle = L"Select DLL to inspect and inject";
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&dialog)) {
        dialog_error = CommDlgExtendedError();
        return false;
    }

    const std::wstring wide_path(selected);
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                         wide_path.data(), static_cast<int>(wide_path.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size == 0) {
        dialog_error = GetLastError();
        return false;
    }
    path.resize(size);
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            wide_path.data(), static_cast<int>(wide_path.size()),
                            path.data(), size, nullptr, nullptr) != size) {
        dialog_error = GetLastError();
        return false;
    }
    dialog_error = 0;
    return true;
}

void print_usage() {
    std::cout << "NtMapper - Windows PE inspection and manual-map demo\n\n"
              << "Usage:\n"
              << "  NtMapper inspect <dll-path>\n"
              << "  NtMapper inject <process.exe> <dll-path> "
                 "[--profile QueryPerformanceCounter|TranslateMessage]\n"
              << "  NtMapper <process.exe> <dll-path> [1|2]  (legacy syntax)\n"
              << "  NtMapper  (interactive mode for Visual Studio F5)\n";
}

void print_report(const PeInspector::Report& report) {
    std::cout << "PE32+ DLL | AMD64 | image " << report.image_size << " bytes"
              << " | base 0x" << std::hex << report.preferred_base
              << " | entry RVA 0x" << report.entry_point << std::dec << '\n';
    std::cout << "Sections (" << report.sections.size() << "):\n";
    for (const auto& section : report.sections) {
        std::cout << "  " << std::left << std::setw(8) << section.name << std::right
                  << " RVA 0x" << std::hex << section.virtual_address
                  << " raw 0x" << section.raw_offset << std::dec
                  << " (" << section.raw_size << " bytes)\n";
    }
    std::cout << "Imported DLLs (" << report.imports.size() << "):";
    for (const auto& name : report.imports) std::cout << " " << name;
    std::cout << "\nRelocations: " << report.relocation_blocks << " blocks, "
              << report.relocation_entries << " entries\n";
}

std::vector<std::string> hook_order(bool translate_first) {
    if (translate_first) {
        return { "TranslateMessage", "PeekMessageA", "PeekMessageW", "GetMessageA",
                 "GetMessageW", "DispatchMessageA", "DispatchMessageW",
                 "QueryPerformanceCounter", "EnterCriticalSection" };
    }
    return { "QueryPerformanceCounter", "EnterCriticalSection", "TranslateMessage",
             "PeekMessageA", "PeekMessageW", "GetMessageA", "GetMessageW",
             "DispatchMessageA", "DispatchMessageW" };
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc >= 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        print_usage();
        return 0;
    }

    const bool interactive = argc < 2;
    bool inspect_only = false;
    bool translate_first = false;
    std::string process_arg;
    std::string path;
    if (interactive) {
        std::cout << "NtMapper interactive mode (use --help for commands)\n"
                  << "Target process name: " << std::flush;
        if (!std::getline(std::cin, process_arg) || process_arg.empty()) {
            std::cerr << "Error: process name is required.\n";
            return 2;
        }
        std::cout << "Opening DLL file picker...\n" << std::flush;
        DWORD dialog_error = 0;
        if (!choose_dll(path, dialog_error)) {
            if (dialog_error == 0) {
                std::cout << "DLL selection cancelled.\n";
                return 2;
            }
            std::cerr << "Error: file picker failed (code " << dialog_error << ").\n";
            return 3;
        }
        std::cout << "Selected DLL: " << path << '\n';
        std::cout << "Function to try first [1=QueryPerformanceCounter (default), "
                     "2=TranslateMessage]: " << std::flush;
        std::string choice;
        if (!std::getline(std::cin, choice)) return 2;
        if (choice == "2") translate_first = true;
        else if (!choice.empty() && choice != "1") {
            std::cerr << "Error: choose 1 (QueryPerformanceCounter) "
                         "or 2 (TranslateMessage).\n";
            return 2;
        }
    } else {
        const std::string command = argv[1];
        inspect_only = command == "inspect";
        const bool named_inject = command == "inject";
        const int first_arg = inspect_only || named_inject ? 2 : 1;
        if ((inspect_only && argc != 3) || (!inspect_only && argc < first_arg + 2)) {
            print_usage();
            return 2;
        }
        if (!inspect_only && argc > first_arg + 2) {
            const std::string flag = argv[first_arg + 2];
            const bool modern = flag == "--profile" && argc == first_arg + 4;
            const bool legacy = !named_inject && argc == first_arg + 3;
            if (!modern && !legacy) { print_usage(); return 2; }
            const std::string choice = modern ? argv[first_arg + 3] : flag;
            if (choice == "TranslateMessage" || choice == "translate" ||
                choice == "ui" || choice == "2") translate_first = true;
            else if (choice != "QueryPerformanceCounter" && choice != "qpc" &&
                     choice != "performance" && choice != "1") {
                print_usage();
                return 2;
            }
        }
        path = argv[first_arg + (inspect_only ? 0 : 1)];
        if (!inspect_only) process_arg = argv[first_arg];
    }

    std::vector<uint8_t> bytes;
    if (!read_file(path, bytes)) {
        std::cerr << "Error: cannot read DLL file: " << path << '\n';
        return 3;
    }
    PeInspector::Report report;
    std::string error;
    if (!PeInspector::inspect(bytes, report, error)) {
        std::cerr << "Error: " << error << '\n';
        return 3;
    }
    print_report(report);
    if (inspect_only) return 0;

    std::wstring process_name;
    if (!to_wide(process_arg, process_name)) {
        std::cerr << "Error: process name must be valid UTF-8.\n";
        return 2;
    }
    NtApi api{};
    if (!NtLdr::Initialize(api)) {
        std::cerr << "Error: failed to resolve native Windows APIs.\n";
        return 4;
    }
    const DWORD pid = NtLdr::FindProcessId(api, process_name.c_str());
    if (!pid) {
        std::cerr << "Error: process not found: " << process_arg << '\n';
        return 4;
    }
    std::cout << "Target PID: " << pid << " | function tried first: "
              << (translate_first ? "TranslateMessage" : "QueryPerformanceCounter") << '\n';
    if (!NtMapper::NtManualMap(api, pid, bytes, hook_order(translate_first))) {
        std::cerr << "Injection failed.\n";
        return 5;
    }
    std::cout << "Injection completed.\n";
    return 0;
}
