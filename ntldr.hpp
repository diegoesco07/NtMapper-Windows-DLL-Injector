#ifndef NTLDR_HPP
#define NTLDR_HPP

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

#pragma comment(lib, "ntdll.lib")

// ============================================================
//  NtLdr — Native Windows NT Function Resolver & Process Helper
//  Resolves functions directly from ntdll via PEB walking.
// ============================================================

typedef struct _NT_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NT_UNICODE_STRING, *PNT_UNICODE_STRING;

typedef struct _NT_ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} NT_ANSI_STRING, *PNT_ANSI_STRING;

typedef struct _NT_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} NT_CLIENT_ID, *PNT_CLIENT_ID;

// NT Function Typedefs
typedef NTSTATUS(NTAPI* fnNtOpenProcess)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PNT_CLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI* fnNtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList);

typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(
    HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID Arg1, PVOID Arg2, PVOID Arg3);

typedef NTSTATUS(NTAPI* fnNtOpenThread)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PNT_CLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* fnNtSetInformationThread)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);

typedef NTSTATUS(NTAPI* fnNtFreeVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten);

typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);

typedef NTSTATUS(NTAPI* fnLdrLoadDll)(
    PWSTR SearchPath, PULONG Flags,
    PNT_UNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

typedef NTSTATUS(NTAPI* fnLdrGetProcedureAddress)(
    HMODULE ModuleHandle, PNT_ANSI_STRING FunctionName,
    ULONG Ordinal, PVOID* FunctionAddress);

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS(NTAPI* fnNtDelayExecution)(
    BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

typedef VOID(NTAPI* fnRtlFillMemory)(PVOID Dest, SIZE_T Length, UCHAR Fill);

typedef VOID(NTAPI* fnRtlInitAnsiString)(PNT_ANSI_STRING DestString, PCSZ SourceString);

typedef VOID(NTAPI* fnRtlInitUnicodeString)(PNT_UNICODE_STRING DestString, PCWSTR SourceString);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

struct NtApi {
    fnNtOpenProcess            NtOpenProcess;
    fnNtClose                  NtClose;
    fnNtTerminateProcess       NtTerminateProcess;
    fnNtWaitForSingleObject    NtWaitForSingleObject;
    fnNtCreateThreadEx         NtCreateThreadEx;
    fnNtQueueApcThread         NtQueueApcThread;
    fnNtOpenThread             NtOpenThread;
    fnNtSetInformationThread   NtSetInformationThread;
    fnNtAllocateVirtualMemory  NtAllocateVirtualMemory;
    fnNtFreeVirtualMemory      NtFreeVirtualMemory;
    fnNtProtectVirtualMemory   NtProtectVirtualMemory;
    fnNtWriteVirtualMemory     NtWriteVirtualMemory;
    fnNtReadVirtualMemory      NtReadVirtualMemory;
    fnLdrLoadDll               LdrLoadDll;
    fnLdrGetProcedureAddress   LdrGetProcedureAddress;
    fnNtQuerySystemInformation NtQuerySystemInformation;
    fnNtDelayExecution          NtDelayExecution;
    fnRtlFillMemory             RtlFillMemory;
    fnRtlInitAnsiString         RtlInitAnsiString;
    fnRtlInitUnicodeString      RtlInitUnicodeString;
    fnNtQueryInformationProcess NtQueryInformationProcess;
};

namespace NtLdr {

    inline PPEB GetPeb() {
    #ifdef _WIN64
        return (PPEB)__readgsqword(0x60);
    #else
        return (PPEB)__readfsdword(0x30);
    #endif
    }

    inline HMODULE GetModuleByHash(DWORD hash) {
        PPEB pPeb = GetPeb();
        PPEB_LDR_DATA pLdr = pPeb->Ldr;
        PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
        PLIST_ENTRY pEntry = pHead->Flink;

        while (pEntry != pHead) {
            PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(
                pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (pModule->FullDllName.Buffer) {
                DWORD nameHash = 0;
                PWSTR name = pModule->FullDllName.Buffer;
                PWSTR lastSlash = name;
                for (PWSTR p = name; *p; p++) {
                    if (*p == L'\\' || *p == L'/') lastSlash = p + 1;
                }
                for (PWSTR p = lastSlash; *p; p++) {
                    WCHAR c = (*p >= L'A' && *p <= L'Z') ? (*p + 32) : *p;
                    nameHash = ((nameHash << 5) + nameHash) + c;
                }

                if (nameHash == hash) {
                    return (HMODULE)pModule->DllBase;
                }
            }
            pEntry = pEntry->Flink;
        }
        return NULL;
    }

    inline DWORD HashStringW(const wchar_t* str) {
        DWORD hash = 0;
        while (*str) {
            WCHAR c = (*str >= L'A' && *str <= L'Z') ? (*str + 32) : *str;
            hash = ((hash << 5) + hash) + c;
            str++;
        }
        return hash;
    }

    inline DWORD HashStringA(const char* str) {
        DWORD hash = 0;
        while (*str) {
            hash = ((hash << 5) + hash) + *str;
            str++;
        }
        return hash;
    }

    inline PVOID GetProcByHash(HMODULE hModule, DWORD funcHash) {
        if (!hModule) return nullptr;

        BYTE* base = (BYTE*)hModule;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(
            base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names = (DWORD*)(base + exports->AddressOfNames);
        WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            char* name = (char*)(base + names[i]);
            DWORD h = HashStringA(name);
            if (h == funcHash) {
                return (PVOID)(base + functions[ordinals[i]]);
            }
        }
        return nullptr;
    }

    inline bool Initialize(NtApi& api) {
        HMODULE hNtdll = GetModuleByHash(HashStringW(L"ntdll.dll"));
        if (!hNtdll) return false;

        #define RESOLVE(func, name) \
            api.func = (fn##func)GetProcByHash(hNtdll, HashStringA(name)); \
            if (!api.func) return false;

        RESOLVE(NtOpenProcess,            "NtOpenProcess");
        RESOLVE(NtClose,                  "NtClose");
        RESOLVE(NtTerminateProcess,       "NtTerminateProcess");
        RESOLVE(NtWaitForSingleObject,    "NtWaitForSingleObject");
        RESOLVE(NtCreateThreadEx,         "NtCreateThreadEx");
        RESOLVE(NtQueueApcThread,         "NtQueueApcThread");
        RESOLVE(NtOpenThread,             "NtOpenThread");
        RESOLVE(NtSetInformationThread,   "NtSetInformationThread");
        RESOLVE(NtAllocateVirtualMemory,  "NtAllocateVirtualMemory");
        RESOLVE(NtFreeVirtualMemory,      "NtFreeVirtualMemory");
        RESOLVE(NtProtectVirtualMemory,   "NtProtectVirtualMemory");
        RESOLVE(NtWriteVirtualMemory,     "NtWriteVirtualMemory");
        RESOLVE(NtReadVirtualMemory,      "NtReadVirtualMemory");
        RESOLVE(LdrLoadDll,               "LdrLoadDll");
        RESOLVE(LdrGetProcedureAddress,   "LdrGetProcedureAddress");
        RESOLVE(NtQuerySystemInformation, "NtQuerySystemInformation");
        RESOLVE(NtDelayExecution,         "NtDelayExecution");
        RESOLVE(RtlFillMemory,            "RtlFillMemory");
        RESOLVE(RtlInitAnsiString,        "RtlInitAnsiString");
        RESOLVE(RtlInitUnicodeString,     "RtlInitUnicodeString");
        RESOLVE(NtQueryInformationProcess, "NtQueryInformationProcess");

        #undef RESOLVE
        return true;
    }

    inline void NtDelay(NtApi& api, DWORD milliseconds) {
        LARGE_INTEGER interval;
        interval.QuadPart = -((LONGLONG)milliseconds * 10000);
        api.NtDelayExecution(FALSE, &interval);
    }

    typedef struct _MY_SYSTEM_PROCESS_INFO {
        ULONG           NextEntryOffset;
        ULONG           NumberOfThreads;
        LARGE_INTEGER   WorkingSetPrivateSize;
        ULONG           HardFaultCount;
        ULONG           NumberOfThreadsHighWatermark;
        ULONGLONG       CycleTime;
        LARGE_INTEGER   CreateTime;
        LARGE_INTEGER   UserTime;
        LARGE_INTEGER   KernelTime;
        UNICODE_STRING  ImageName;
        LONG            BasePriority;
        HANDLE          UniqueProcessId;
        HANDLE          InheritedFromUniqueProcessId;
    } MY_SYSTEM_PROCESS_INFO;

    inline DWORD FindProcessId(NtApi& api, const wchar_t* processName) {
        ULONG bufferSize = 1024 * 1024 * 2;
        PVOID buffer = nullptr;
        SIZE_T regionSize = bufferSize;

        NTSTATUS status = api.NtAllocateVirtualMemory(
            (HANDLE)-1, &buffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (status != 0 || !buffer) return 0;

        status = api.NtQuerySystemInformation(5, buffer, (ULONG)regionSize, nullptr);
        if (status != 0) {
            api.NtFreeVirtualMemory((HANDLE)-1, &buffer, &regionSize, MEM_RELEASE);
            return 0;
        }

        DWORD pid = 0;
        MY_SYSTEM_PROCESS_INFO* entry = (MY_SYSTEM_PROCESS_INFO*)buffer;

        while (true) {
            if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
                USHORT numChars = entry->ImageName.Length / sizeof(WCHAR);
                USHORT targetLen = 0;
                while (processName[targetLen]) targetLen++;

                if (numChars == targetLen) {
                    bool match = true;
                    for (USHORT i = 0; i < numChars; i++) {
                        WCHAR a = entry->ImageName.Buffer[i];
                        WCHAR b = processName[i];
                        if (a >= L'A' && a <= L'Z') a += 32;
                        if (b >= L'A' && b <= L'Z') b += 32;
                        if (a != b) { match = false; break; }
                    }
                    if (match) {
                        pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
                        break;
                    }
                }
            }

            if (entry->NextEntryOffset == 0) break;
            entry = (MY_SYSTEM_PROCESS_INFO*)((BYTE*)entry + entry->NextEntryOffset);
        }

        api.NtFreeVirtualMemory((HANDLE)-1, &buffer, &regionSize, MEM_RELEASE);
        return pid;
    }
}

#endif // NTLDR_HPP
