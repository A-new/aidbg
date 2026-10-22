// Anti-debug probe: runs the classic al-khaser style checks against *itself*
// and reports which of them fire. Used to validate aidbg's hiding (L1 + L2).
//
//   antidbg_probe.exe [outfile]
//
// Writes one "name=0|1" line per check to the outfile (and stdout), and the
// process exit code is the number of detections.
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtClose_t)(HANDLE);
typedef LONG(NTAPI* NtYieldExecution_t)(void);
typedef LONG(NTAPI* NtSetInformationThread_t)(HANDLE, ULONG, PVOID, ULONG);

static NtQueryInformationProcess_t pNtQIP;
static NtQuerySystemInformation_t pNtQSI;
static NtQueryObject_t pNtQO;
static NtClose_t pNtClose;
static NtYieldExecution_t pNtYield;
static NtSetInformationThread_t pNtSIT;

static FILE* g_out;
static int g_detected = 0;

static void report(const char* name, int detected) {
    if (detected) g_detected++;
    fprintf(g_out, "%s=%d\n", name, detected);
    fprintf(g_out == stdout ? stderr : stdout, "[probe] %-24s %s\n", name,
            detected ? "DETECTED" : "clean");
    fflush(g_out);
}

int main(int argc, char** argv) {
    g_out = argc > 1 ? fopen(argv[1], "w") : stdout;
    if (!g_out) g_out = stdout;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQIP = (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtQSI = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQO = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");
    pNtClose = (NtClose_t)GetProcAddress(ntdll, "NtClose");
    pNtYield = (NtYieldExecution_t)GetProcAddress(ntdll, "NtYieldExecution");
    pNtSIT = (NtSetInformationThread_t)GetProcAddress(ntdll, "NtSetInformationThread");

#ifdef _WIN64
    const int ptr = 8;
    const ULONG off_ntglobalflag = 0xBC, off_heap_flags = 0x70, off_heap_force = 0x74;
#else
    const int ptr = 4;
    const ULONG off_ntglobalflag = 0x68, off_heap_flags = 0x40, off_heap_force = 0x44;
#endif

    // 1. IsDebuggerPresent
    report("is_debugger_present", IsDebuggerPresent() ? 1 : 0);

    // 2. PEB.BeingDebugged (direct read)
    {
        LONG st;
        ULONG rl = 0;
        // NB: PROCESS_BASIC_INFORMATION accepts exactly 48 bytes on x64 (24 on
        // x86); a bigger buffer comes back with garbage pointers
        unsigned char buf[48] = {0};
        st = pNtQIP((HANDLE)-1, 0, buf, ptr == 8 ? 48 : 24, &rl);
        (void)st;
        unsigned char* peb = ptr == 8 ? (unsigned char*)(*(unsigned long long*)(buf + 8))
                                      : (unsigned char*)(*(unsigned int*)(buf + 4));
        report("peb_being_debugged", peb[2] ? 1 : 0);

        // 3. NtGlobalFlag
        unsigned int ngf = ptr == 8 ? *(unsigned int*)(peb + off_ntglobalflag)
                                    : *(unsigned int*)(peb + off_ntglobalflag);
        report("peb_ntglobalflag", (ngf & 0x70) ? 1 : 0);
    }

    // 4. heap Flags / ForceFlags
    {
        HANDLE heap = GetProcessHeap();
        unsigned int f = *(unsigned int*)((char*)heap + off_heap_flags);
        unsigned int ff = *(unsigned int*)((char*)heap + off_heap_force);
        int bad = 0;
        if (f & (0x20 | 0x40 | 0x10000000)) bad = 1;
        if (ff) bad = 1;
        report("heap_flags", bad);
    }

    // 5. startup info leak
    {
        STARTUPINFOA si;
        memset(&si, 0, sizeof(si));
        GetStartupInfoA(&si);
        int bad = (si.dwX != 0 || si.dwY != 0 || si.dwXSize != 0 || si.dwYSize != 0) ? 1 : 0;
        report("startup_info", bad);
    }

    // 6. NtQueryInformationProcess(ProcessDebugPort)
    {
        unsigned long long v = 0;
        LONG st = pNtQIP((HANDLE)-1, 7, &v, ptr, 0);
        int bad = (st >= 0 && v != 0) ? 1 : 0;
        report("process_debug_port", bad);
    }

    // 7. NtQueryInformationProcess(ProcessDebugObjectHandle)
    {
        unsigned long long v = 0xDEAD;
        LONG st = pNtQIP((HANDLE)-1, 30, &v, ptr, 0);
        int bad = (st >= 0 && v != 0) ? 1 : 0;
        report("process_debug_object", bad);
    }

    // 8. NtQueryInformationProcess(ProcessDebugFlags)
    {
        unsigned int v = 0x1234;
        LONG st = pNtQIP((HANDLE)-1, 31, &v, 4, 0);
        int bad = (st >= 0 && v == 0) ? 1 : 0;
        report("process_debug_flags", bad);
    }

    // 9. NtQuerySystemInformation(SystemKernelDebuggerInformation)
    {
        unsigned char kd[2] = {0xFF, 0xFF};
        LONG st = pNtQSI(35, kd, sizeof(kd), 0);
        int bad = (st >= 0 && (kd[0] != 0 || kd[1] == 0)) ? 1 : 0;
        report("kernel_debugger", bad);
    }

    // 10. NtQueryObject(ObjectTypesInformation): DebugObject count
    {
        ULONG need = 0;
        pNtQO(0, 3, 0, 0, &need);
        if (need && need < 1 << 20) {
            unsigned char* buf = (unsigned char*)malloc(need + 64);
            memset(buf, 0, need + 64);
            LONG st = pNtQO(0, 3, buf, need + 64, 0);
            int bad = 0;
            if (st >= 0) {
                unsigned int count = 0;
                memcpy(&count, buf, 4);
                size_t off = (4 + ptr - 1) & ~(size_t)(ptr - 1);
                size_t struct_size = ptr == 8 ? 0x68 : 0x60;
                for (unsigned int i = 0; i < count; ++i) {
                    unsigned short name_len = 0, name_max = 0;
                    memcpy(&name_len, buf + off, 2);
                    memcpy(&name_max, buf + off + 2, 2);
                    unsigned long long name_ptr = 0;
                    if (ptr == 8)
                        memcpy(&name_ptr, buf + off + 8, 8);
                    else {
                        unsigned int p32 = 0;
                        memcpy(&p32, buf + off + 4, 4);
                        name_ptr = p32;
                    }
                    wchar_t* nm = (wchar_t*)(size_t)name_ptr;
                    if (nm && wcsncmp(nm, L"DebugObject", 11) == 0) {
                        unsigned int objs = 0;
                        memcpy(&objs, buf + off + (ptr == 8 ? 16 : 8), 4);
                        if (objs > 0) bad = 1;
                    }
                    size_t next = off + struct_size + ((name_max + ptr - 1) / ptr) * ptr;
                    if (next <= off) break;
                    off = next;
                }
            }
            free(buf);
            report("debugobject_types", bad);
        } else {
            report("debugobject_types", 0);
        }
    }

    // 11. invalid handle close (exception based)
    {
        int raised = 0;
        __try {
            pNtClose((HANDLE)(size_t)0x99999999);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            raised = 1;
        }
        report("close_invalid_handle", raised);
    }

    // 12. CheckRemoteDebuggerPresent
    {
        BOOL present = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
        report("remote_debugger", present ? 1 : 0);
    }

    // 13. hardware breakpoints in our own context
    {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        int bad = (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ? 1 : 0;
        report("hardware_breakpoints", bad);
    }

    // 14. ThreadHideFromDebugger followed by a query: if the thread really is
    //     hidden, later debug events stop reaching the debugger
    {
        LONG st = pNtSIT((HANDLE)-2, 17, 0, 0);
        report("thread_hide_from_debugger", 0);  // informational
        (void)st;
    }

    // 15. NtYieldExecution: al-khaser itself documents this check as hopeless
    //     (it also fires for unrelated busy systems), so only report the raw
    //     count - it never contributes to the detection verdict.
    {
        int yields = 0;
        for (int i = 0; i < 8; ++i) {
            Sleep(2);
            if (pNtYield() != 0x40000024) yields++;
        }
        fprintf(g_out, "nt_yield_execution_raw=%d\n", yields);
    }

    fprintf(g_out == stdout ? stderr : stdout, "[probe] total detections: %d\n", g_detected);
    if (g_out != stdout) fclose(g_out);
    return g_detected;
}
