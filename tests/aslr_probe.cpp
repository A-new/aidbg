// Probe: which technique actually pins a process's main image to its PE
// ImageBase? Compares (A) process-creation mitigation policy and (B) clearing
// the DYNAMIC_BASE flag in the PE header of a patched copy.
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static uint64_t module_base_of(HANDLE proc) {
    HMODULE mods[1];
    DWORD needed = 0;
    if (EnumProcessModules(proc, mods, sizeof(mods), &needed)) return (uint64_t)mods[0];
    return 0;
}

static int run_case(const char* label, const wchar_t* exe, bool use_policy, bool patch_copy) {
    std::wstring path = exe;
    if (patch_copy) {
        // copy the target and clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        std::wstring copy = path + L".noaslr.exe";
        if (!CopyFileW(path.c_str(), copy.c_str(), FALSE)) {
            printf("%-22s CopyFile failed\n", label);
            return 1;
        }
        HANDLE h = CreateFileW(copy.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            printf("%-22s open copy failed\n", label);
            return 1;
        }
        DWORD lo = GetFileSize(h, nullptr);
        std::vector<uint8_t> buf(lo);
        DWORD got = 0;
        ReadFile(h, buf.data(), lo, &got, nullptr);
        uint32_t lfanew = *(uint32_t*)(buf.data() + 0x3C);
        uint8_t* opt = buf.data() + lfanew + 4 + 20;
        uint16_t magic = *(uint16_t*)opt;
        // DllCharacteristics at optional header +0x46 (PE32 and PE32+)
        uint16_t dllch = *(uint16_t*)(opt + 0x46);
        dllch &= ~(uint16_t)0x0040;   // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        dllch &= ~(uint16_t)0x0020;   // HIGH_ENTROPY_VA
        *(uint16_t*)(opt + 0x46) = dllch;
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        WriteFile(h, buf.data(), got, &got, nullptr);
        CloseHandle(h);
        path = copy;
        (void)magic;
    }

    STARTUPINFOEXW siex;
    std::memset(&siex, 0, sizeof(siex));
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    std::vector<uint8_t> attr_buf;
    bool have_attrs = false;
    if (use_policy) {
        SIZE_T sz = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &sz);
        attr_buf.resize(sz);
        LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)attr_buf.data();
        if (InitializeProcThreadAttributeList(attrs, 1, 0, &sz)) {
            DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF |
                             PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF;
            if (UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                          &policy, sizeof(policy), nullptr, nullptr)) {
                siex.lpAttributeList = attrs;
                have_attrs = true;
            }
        }
        printf("%-22s policy attr setup: %s\n", label, have_attrs ? "OK" : "FAILED");
    }
    DWORD flags = DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW |
                  (have_attrs ? EXTENDED_STARTUPINFO_PRESENT : 0);

    PROCESS_INFORMATION pi;
    std::memset(&pi, 0, sizeof(pi));
    std::wstring cmd = L"\"" + path + L"\"";
    if (!CreateProcessW(path.c_str(), &cmd[0], nullptr, nullptr, FALSE, flags, nullptr,
                        nullptr, &siex.StartupInfo, &pi)) {
        printf("%-22s CreateProcess failed: %lu\n", label, GetLastError());
        return 1;
    }
    if (have_attrs) DeleteProcThreadAttributeList(siex.lpAttributeList);

    // pump debug events until CREATE_PROCESS
    uint64_t base = 0;
    for (int i = 0; i < 20 && !base; ++i) {
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, 3000)) break;
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            base = (uint64_t)ev.u.CreateProcessInfo.lpBaseOfImage;
            CloseHandle(ev.u.CreateProcessInfo.hFile);
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("%-22s base = 0x%llx\n", label, (unsigned long long)base);
    return 0;
}

int main() {
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    const wchar_t* x64 = L"D:\\crack\\debug\\code\\aidbg\\tests\\target.exe";
    const wchar_t* x86 = L"D:\\crack\\debug\\code\\aidbg\\tests\\target32.exe";

    printf("x64 target (ImageBase 0x140000000), x86 target (ImageBase 0x400000)\n\n");
    run_case("x64 baseline", x64, false, false);
    run_case("x64 policy", x64, true, false);
    run_case("x64 patched", x64, false, true);
    printf("\n");
    run_case("x86 baseline", x86, false, false);
    run_case("x86 policy", x86, true, false);
    run_case("x86 patched", x86, false, true);
    return 0;
}
