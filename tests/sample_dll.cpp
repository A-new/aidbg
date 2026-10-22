// Minimal DLL used to demonstrate DLL debugging through a host process.
#include <windows.h>

extern "C" __declspec(dllexport) int __stdcall SampleEntry(int x) {
    volatile int acc = 0;
    for (int i = 0; i < 100; ++i) acc += i * x;  // give breakpoints something to hit
    return acc;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
