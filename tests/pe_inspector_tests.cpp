// language: C++, file: tests/pe_inspector_tests.cpp, target: Windows 11 x64, MSVC
#include "pe_inspector.hpp"
#include <cstring>
#include <iostream>
#include <vector>

template <typename T>
void write_at(std::vector<uint8_t>& bytes, size_t offset, const T& value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

std::vector<uint8_t> sample_image() {
    std::vector<uint8_t> bytes(0x400, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    write_at(bytes, 0, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_DLL;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.ImageBase = 0x180000000;
    nt.OptionalHeader.SizeOfImage = 0x2000;
    nt.OptionalHeader.SizeOfHeaders = 0x200;
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x1000, 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR)};
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1080, 12};
    write_at(bytes, 0x80, nt);

    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".text", 5);
    section.VirtualAddress = 0x1000;
    section.Misc.VirtualSize = 0x200;
    section.PointerToRawData = 0x200;
    section.SizeOfRawData = 0x200;
    write_at(bytes, 0x80 + sizeof(nt), section);

    IMAGE_IMPORT_DESCRIPTOR imported{};
    imported.Name = 0x1050;
    write_at(bytes, 0x200, imported);
    std::memcpy(bytes.data() + 0x250, "KERNEL32.dll", 13);

    IMAGE_BASE_RELOCATION block{};
    block.VirtualAddress = 0x1000;
    block.SizeOfBlock = 12;
    write_at(bytes, 0x280, block);
    const WORD entry = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x20);
    write_at(bytes, 0x288, entry);
    return bytes;
}

int main() {
    auto bytes = sample_image();
    PeInspector::Report report;
    std::string error;
    if (!PeInspector::inspect(bytes, report, error) || report.sections.size() != 1 ||
        report.imports.size() != 1 || report.imports[0] != "KERNEL32.dll" ||
        report.relocation_blocks != 1 || report.relocation_entries != 2) {
        std::cerr << "Valid PE fixture failed: " << error << '\n';
        return 1;
    }
    bytes.resize(40);
    if (PeInspector::inspect(bytes, report, error)) {
        std::cerr << "Truncated image accepted\n";
        return 1;
    }
    bytes = sample_image();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + 0x80);
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    if (PeInspector::inspect(bytes, report, error) || error.find("x64") == std::string::npos) {
        std::cerr << "x86 image accepted\n";
        return 1;
    }
    bytes = sample_image();
    auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(bytes.data() + 0x80 + sizeof(IMAGE_NT_HEADERS64));
    section->PointerToRawData = 0x3f0;
    if (PeInspector::inspect(bytes, report, error)) {
        std::cerr << "Out-of-bounds section accepted\n";
        return 1;
    }
    bytes = sample_image();
    auto* imported = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(bytes.data() + 0x200);
    imported->Name = 0x3000;
    if (PeInspector::inspect(bytes, report, error)) {
        std::cerr << "Out-of-bounds import accepted\n";
        return 1;
    }
    std::cout << "PE inspection tests passed\n";
    return 0;
}
