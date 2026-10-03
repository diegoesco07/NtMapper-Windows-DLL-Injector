// language: C++, file: demo/demo_target.cpp, target: Windows 11 x64, MSVC
#include <windows.h>
#include <iostream>

int main() {
    HANDLE loaded = CreateEventW(nullptr, TRUE, FALSE, L"Local\\NtMapperDemoLoaded");
    if (!loaded) {
        std::cerr << "Cannot create demo event: " << GetLastError() << '\n';
        return 1;
    }
    std::cout << "DEMO_READY pid=" << GetCurrentProcessId() << std::endl;
    LARGE_INTEGER counter{};
    for (int i = 0; i < 3000; ++i) {
        QueryPerformanceCounter(&counter);
        if (WaitForSingleObject(loaded, 0) == WAIT_OBJECT_0) {
            std::cout << "DEMO_LOADED" << std::endl;
            // Leave time for the injector to observe IAT restoration and finish cleanup.
            Sleep(2000);
            CloseHandle(loaded);
            return 0;
        }
        Sleep(10);
    }
    std::cerr << "DEMO_TIMEOUT" << std::endl;
    CloseHandle(loaded);
    return 2;
}
