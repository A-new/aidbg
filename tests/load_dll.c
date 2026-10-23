// Loads a dumped DLL and calls its export - end-to-end validation that a
// repaired dump (imports rebuilt, relocations restored) is loadable again.
// mode: (none) full load + call | data LOAD_LIBRARY_AS_DATAFILE (map only) |
// norésolve DONT_RESOLVE_DLL_REFERENCES (map + no init)
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

typedef int(__stdcall* Fn)(int);

static LONG WINAPI crash(EXCEPTION_POINTERS* ep) {
    FILE* out = fopen("load_dll_result.txt", "a");
    if (out) {
        fprintf(out, "crash: code=%08lx addr=%p\n",
                ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
        fclose(out);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static void report(const char* fmt, ...) {
    FILE* out = fopen("load_dll_result.txt", "w");
    if (!out) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fclose(out);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    SetUnhandledExceptionFilter(crash);
    if (argc < 2) return 2;
    DWORD flags = 0;
    if (argc > 2 && !strcmp(argv[2], "data")) flags = LOAD_LIBRARY_AS_DATAFILE;
    if (argc > 2 && !strcmp(argv[2], "noresolve"))
        flags = DONT_RESOLVE_DLL_REFERENCES;
    HMODULE h = LoadLibraryExA(argv[1], NULL, flags);
    if (!h) {
        report("load failed: %lu (flags=%lu)\n", GetLastError(), flags);
        return 1;
    }
    if (flags) {
        report("mapped ok (flags=%lu)\n", flags);
        return 0;
    }
    Fn fn = (Fn)GetProcAddress(h, "SampleEntry");
    if (!fn) {
        report("no SampleEntry: %lu\n", GetLastError());
        return 3;
    }
    int r = fn(41);
    report("SampleEntry(41) = %d\n", r);
    return r == 202950 ? 0 : 4;
}
