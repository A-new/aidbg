// Minimal DLL host used by aidbg to debug DLL targets: a DLL cannot be created
// as a process, so aidbg runs this stub, which loads the DLL (executing its
// DllMain) and optionally calls one export, then keeps the DLL mapped until
// the debugger ends the session.
//
//   dllhost.exe <dll> [export]
//
// The export is invoked as `void WINAPI fn(HWND, HINSTANCE, LPSTR, int)` -
// the rundll32 convention (x86 exports must clean their own stack, i.e.
// stdcall/thiscall-compatible). Without an export the host simply keeps the
// DLL loaded, which is enough for DllMain breakpoints and manual control.
#include <windows.h>

typedef void(WINAPI* entry_fn)(void*, void*, void*, int);

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return 2;

    HMODULE mod = LoadLibraryW(argv[1]);
    if (!mod) return 1;

    if (argc >= 3 && argv[2][0]) {
        // export names are plain ASCII; convert by truncation
        char name[128];
        size_t i = 0;
        for (; argv[2][i] && i + 1 < sizeof(name); ++i) name[i] = (char)argv[2][i];
        name[i] = 0;
        entry_fn fn = (entry_fn)GetProcAddress(mod, name);
        if (!fn) return 3;  // export not found: end visibly instead of idling
        fn(0, 0, 0, 0);
    }

    // stay alive with the DLL mapped; the debugger decides when this ends
    for (;;) Sleep(1000);
    return 0;
}
