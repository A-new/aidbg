// Test target for import analysis and import-call tracing.
//
// Contains both kinds of import reference:
//   - direct IAT calls            (call [rip+x]  -> a real API pointer)
//   - an indirect call resolved   (GetProcAddress at runtime, then call rax)
//     the way VMProtect/Themida leave imports behind: nothing in the code
//     points at the API, only the runtime value does.
#include <windows.h>
#include <stdio.h>

typedef DWORD(WINAPI* GetTickCount_t)(void);
typedef void(WINAPI* Sleep_t)(DWORD);
typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);

volatile DWORD g_sink;

int main(void) {
    // direct imports through the IAT
    DWORD t = GetTickCount();
    Sleep(1);
    g_sink += t & 0xF;

    // opaque resolver: the call below is `call rax`, nothing statically
    // identifies which API it reaches
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC p = GetProcAddress(k32, "GetTickCount");
    GetTickCount_t fn = (GetTickCount_t)p;
    if (fn) {
        g_sink += fn() & 0xF;
    }

    FARPROC ps = GetProcAddress(k32, "Sleep");
    Sleep_t fs = (Sleep_t)ps;
    if (fs) fs(1);

    FARPROC ch = GetProcAddress(k32, "CloseHandle");
    CloseHandle_t fc = (CloseHandle_t)ch;
    if (fc) fc(INVALID_HANDLE_VALUE);

    printf("sink=%lu\n", (unsigned long)g_sink);
    return 0;
}
