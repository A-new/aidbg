// Test target: spawns a child process so aidbg's child-process following can be
// verified. Built as x64; the default child (target32.exe) is x86, which also
// exercises mixed-architecture sessions.
#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
    const char* child = (argc > 1) ? argv[1] : "tests\\target32.exe";
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    printf("parent pid=%lu spawning: %s\n", GetCurrentProcessId(), child);
    fflush(stdout);

    char cmd[MAX_PATH * 2];
    snprintf(cmd, sizeof(cmd), "%s", child);
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("child pid=%lu\n", pi.dwProcessId);
        fflush(stdout);
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        printf("CreateProcess failed: %lu\n", GetLastError());
    }
    printf("parent done\n");
    fflush(stdout);
    return 0;
}
