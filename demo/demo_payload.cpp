// language: C++, file: demo/demo_payload.cpp, target: Windows 11 x64, MSVC
#include <windows.h>

extern "C" __declspec(dllexport) int demo_payload_marker() {
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE loaded = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\NtMapperDemoLoaded");
        if (loaded) {
            SetEvent(loaded);
            CloseHandle(loaded);
        }
    }
    return TRUE;
}
