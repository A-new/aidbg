// Test pair for world-stop verification: the parent spawns a copy of itself
// as a child; both increment a global counter every 200 ms and announce each
// tick via OutputDebugString so progress is observable from the debugger.
// The child keeps ASLR (different base than the fixed-base parent), which also
// exercises per-process symbol resolution of the same module.
#include <windows.h>

#include <cstdio>
#include <cstring>

volatile long g_ticks = 0;

static void run_loop(const char* who) {
    for (int i = 0; i < 60; ++i) {
        InterlockedIncrement(&g_ticks);
        char buf[64];
        snprintf(buf, sizeof(buf), "%s tick %d", who, i);
        OutputDebugStringA(buf);
        Sleep(200);
    }
}

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        run_loop("child");
        return 0;
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // spawn the pristine file (not our own renamed-aside patched image): it
    // keeps DYNAMIC_BASE, so the child lands at a different base than the
    // fixed-base parent - the per-process symbol scenario
    char cmd[MAX_PATH * 2];
    snprintf(cmd, sizeof(cmd), "\"tests\\tickpair.exe\" child");
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return 2;
    CloseHandle(pi.hThread);
    run_loop("parent");
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    return 0;
}
