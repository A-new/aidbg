#include "engine/hide.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>

#include "engine/engine.h"
#include "engine/exports.h"
#include "engine/memory.h"
#include "engine/ntview.h"
#include "engine/registers.h"
#include "util/strutil.h"

namespace aj {

namespace {

// ---------------------------------------------------------------- ntdll (ours)

// The debugger forwards emulated calls to the real API through handles it
// duplicated out of the target, so it needs its own ntdll entry points.
using NtQueryInformationProcess_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThread_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtQuerySystemInformation_t = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObject_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationProcess_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtGetContextThread_t = LONG(WINAPI*)(HANDLE, PVOID);
using NtSetContextThread_t = LONG(WINAPI*)(HANDLE, PVOID);

NtQueryInformationProcess_t pNtQIP = nullptr;
NtSetInformationThread_t pNtSIT = nullptr;
NtQuerySystemInformation_t pNtQSI = nullptr;
NtQueryObject_t pNtQO = nullptr;
NtSetInformationProcess_t pNtSIPr = nullptr;
NtGetContextThread_t pNtGetCtx = nullptr;
NtSetContextThread_t pNtSetCtx = nullptr;
bool g_resolved = false;

void resolve_ntdll() {
    if (g_resolved) return;
    g_resolved = true;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    pNtQIP = (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtSIT = (NtSetInformationThread_t)GetProcAddress(ntdll, "NtSetInformationThread");
    pNtQSI = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQO = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");
    pNtSIPr = (NtSetInformationProcess_t)GetProcAddress(ntdll, "NtSetInformationProcess");
    pNtGetCtx = (NtGetContextThread_t)GetProcAddress(ntdll, "NtGetContextThread");
    pNtSetCtx = (NtSetContextThread_t)GetProcAddress(ntdll, "NtSetContextThread");
}

// NTSTATUS values used by the emulated calls
constexpr LONG kStatusSuccess = 0x00000000;
constexpr LONG kStatusPortNotSet = (LONG)0xC0000353;       // ProcessDebugObjectHandle answer
constexpr LONG kStatusInvalidHandle = (LONG)0xC0000008;
constexpr LONG kStatusInfoLengthMismatch = (LONG)0xC0000004;
constexpr LONG kStatusAccessViolation = (LONG)0xC0000005;
constexpr LONG kStatusInvalidParameter = (LONG)0xC000000D;
constexpr LONG kStatusAccessDenied = (LONG)0xC0000022;
constexpr LONG kStatusHandleNotClosable = (LONG)0xC0000235;

// PROCESSINFOCLASS / THREADINFOCLASS / SYSTEM_INFORMATION_CLASS values that
// matter here (verified against phnt and observed behaviour).
constexpr ULONG kProcessBasicInformation = 0;
constexpr ULONG kProcessIoCounters = 2;
constexpr ULONG kProcessDebugPort = 7;
constexpr ULONG kProcessWow64Information = 26;
constexpr ULONG kProcessBreakOnTermination = 29;
constexpr ULONG kProcessDebugObjectHandle = 30;
constexpr ULONG kProcessDebugFlags = 31;
constexpr ULONG kProcessHandleTracing = 32;
constexpr ULONG kThreadHideFromDebugger = 17;
constexpr ULONG kSystemHandleInformation = 16;
constexpr ULONG kSystemKernelDebuggerInformation = 35;
constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kSystemCodeIntegrityInformation = 103;
constexpr ULONG kSystemKernelDebuggerInformationEx = 149;
constexpr ULONG kSystemKernelDebuggerFlags = 163;
constexpr ULONG kSystemCodeIntegrityUnlockInformation = 190;
constexpr ULONG kObjectTypesInformation = 3;  // NtQueryObject: all types
constexpr ULONG kObjectTypeInformation = 2;   // NtQueryObject: one handle's type
constexpr ULONG kObjectHandleFlagInformation = 4;

// heap debug flags (ScyllaHide's PebHider masks, values verified in winnt.h)
constexpr uint32_t kHeapClearableFlags = 0x780000E0;
constexpr uint32_t kHeapClearableForceFlags = 0x60000060;
constexpr uint32_t kHeapFlagsOffsetX64 = 0x70, kHeapForceFlagsOffsetX64 = 0x74;
constexpr uint32_t kHeapFlagsOffsetX86 = 0x40, kHeapForceFlagsOffsetX86 = 0x44;

// PEB / RTL_USER_PROCESS_PARAMETERS offsets. Empirically verified on
// 10.0.26200: x64 NumberOfHeaps at 0x0E8 (0x0EC is MaximumNumberOfHeaps),
// OSBuildNumber at 0x120; the x86 layout follows the same shape.
struct Offsets {
    uint32_t being_debugged, nt_global_flag, params, num_heaps, max_heaps, heaps, os_build;
    uint32_t pp_flags, pp_starting_x, pp_window_flags, pp_show_window_flags;
    uint32_t heap_flags, heap_force_flags;
};
const Offsets& offs(bool is32) {
    static const Offsets o64 = {0x002, 0x0BC, 0x020, 0x0E8, 0x0EC, 0x0F0,
                                0x120, 0x008, 0x088, 0x0A4, 0x0A8,
                                kHeapFlagsOffsetX64, kHeapForceFlagsOffsetX64};
    static const Offsets o32 = {0x002, 0x068, 0x010, 0x088, 0x08C, 0x090,
                                0x0AC, 0x008, 0x04C, 0x068, 0x06C,
                                kHeapFlagsOffsetX86, kHeapForceFlagsOffsetX86};
    return is32 ? o32 : o64;
}

constexpr uint32_t kNtGlobalFlagDebugBits = 0x70;
constexpr uint32_t kImageKeyMissing = 0x4000;  // RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING
constexpr uint16_t kStartfUseShowWindow = 0x0001;
constexpr uint16_t kSwShownormal = 1;

// ------------------------------------------------------------ small helpers

bool rd_bytes(HANDLE proc, uint64_t addr, void* buf, size_t n) {
    std::string e;
    size_t got = 0;
    return read_memory(proc, addr, buf, n, e, &got) && got == n;
}
bool wr_bytes(HANDLE proc, uint64_t addr, const void* buf, size_t n) {
    std::string e;
    return write_memory(proc, addr, buf, n, e);
}
uint64_t rd_ptr(HANDLE proc, uint64_t addr, bool is32) {
    if (is32) {
        uint32_t v = 0;
        return rd_bytes(proc, addr, &v, 4) ? v : 0;
    }
    uint64_t v = 0;
    return rd_bytes(proc, addr, &v, 8) ? v : 0;
}
uint32_t rd_u32(HANDLE proc, uint64_t addr) {
    uint32_t v = 0;
    rd_bytes(proc, addr, &v, 4);
    return v;
}
uint16_t rd_u16(HANDLE proc, uint64_t addr) {
    uint16_t v = 0;
    rd_bytes(proc, addr, &v, 2);
    return v;
}
bool wr_u32(HANDLE proc, uint64_t addr, uint32_t v) { return wr_bytes(proc, addr, &v, 4); }
bool wr_u8(HANDLE proc, uint64_t addr, uint8_t v) { return wr_bytes(proc, addr, &v, 1); }

uint32_t current_os_build() {
    using RtlGetVersion_t = LONG(WINAPI*)(OSVERSIONINFOW*);
    static RtlGetVersion_t fn = (RtlGetVersion_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                                "RtlGetVersion");
    if (!fn) return 0;
    OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    return fn(&vi) == 0 ? (uint32_t)vi.dwBuildNumber : 0;
}

uint32_t explorer_pid() {
    static uint32_t cached = 0;
    if (cached) return cached;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    uint32_t found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    cached = found;
    return found;
}

// debuggee handle value -> handle usable from the debugger. Pseudo handles are
// resolved against the thread that made the call (the stopped thread). The
// returned handle is always an owned duplicate: callers close it, so it must
// never alias a handle the Engine still needs (that mistake once closed the
// target's process handle behind the engine's back).
HANDLE dup_arg_handle(Engine* eng, uint64_t hval, bool is32, bool thread) {
    if (is32) hval &= 0xFFFFFFFFull;
    uint64_t pseudo = thread ? (is32 ? 0xFFFFFFFEull : ~0ull) : (is32 ? 0xFFFFFFFFull : ~0ull);
    HANDLE out = nullptr;
    if (hval == pseudo) {
        HANDLE src = thread ? eng->thread() : eng->process();
        if (!src) return nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), &out, 0, FALSE,
                             DUPLICATE_SAME_ACCESS))
            return nullptr;
        return out;
    }
    if (!DuplicateHandle(eng->process(), (HANDLE)(uintptr_t)hval, GetCurrentProcess(), &out, 0,
                         FALSE, DUPLICATE_SAME_ACCESS))
        return nullptr;
    return out;
}

// ---- calling convention helpers -------------------------------------------

bool read_args(HANDLE proc, const CpuState& st, bool is32, int n, uint64_t* out) {
    if (is32) {
        uint64_t esp = st.gpr[4];
        for (int i = 0; i < n; ++i) {
            uint32_t v = 0;
            if (!rd_bytes(proc, esp + 4 + 4 * (uint64_t)i, &v, 4)) return false;
            out[i] = v;
        }
    } else {
        static const int kRegs[4] = {1, 2, 8, 9};  // rcx, rdx, r8, r9
        for (int i = 0; i < n && i < 4; ++i) out[i] = st.gpr[kRegs[i]];
        for (int i = 4; i < n; ++i) {
            if (!rd_bytes(proc, st.gpr[4] + 0x28 + 8 * (uint64_t)(i - 4), &out[i], 8)) return false;
        }
    }
    return true;
}

// returns to the caller as if the hooked function had executed
bool finish_call(Engine* eng, bool is32, int nargs, uint64_t ret) {
    CpuState st;
    std::string e;
    if (!eng->get_state(st, e)) return false;
    uint64_t retaddr = 0;
    if (is32) {
        uint32_t ra = 0, esp = (uint32_t)st.gpr[4];
        if (!rd_bytes(eng->process(), esp, &ra, 4)) return false;
        retaddr = ra;
        st.gpr[0] = (uint32_t)ret;
        st.rip = retaddr;
        st.gpr[4] = esp + 4 * (uint64_t)(nargs + 1);  // stdcall: callee pops
    } else {
        if (!rd_bytes(eng->process(), st.gpr[4], &retaddr, 8)) return false;
        st.gpr[0] = ret;
        st.rip = retaddr;
        st.gpr[4] += 8;
    }
    return eng->set_state(st, e);
}

uint64_t arg_ptr(bool is32, uint64_t v) { return is32 ? (v & 0xFFFFFFFFull) : v; }

}  // namespace

// ============================================================== configuration

const std::vector<HideKey>& hide_keys() {
    static const std::vector<HideKey> k = {
        {"PebBeingDebugged", &HideConfig::peb_being_debugged, "clear PEB.BeingDebugged"},
        {"PebNtGlobalFlag", &HideConfig::peb_nt_global_flag, "clear NtGlobalFlag debug bits (0x70)"},
        {"PebHeapFlags", &HideConfig::peb_heap_flags, "clear heap Flags/ForceFlags debug bits"},
        {"PebStartupInfo", &HideConfig::peb_startup_info,
         "sanitize RTL_USER_PROCESS_PARAMETERS startup info"},
        {"PebOsBuildNumber", &HideConfig::peb_os_build, "keep the reported OS build plausible"},
        {"HookKuserSharedData", &HideConfig::kuser_debugger,
         "clear KUSER_SHARED_DATA.KdDebuggerEnabled (0x7FFE02D4)"},
        {"NtQueryInformationProcessHook", &HideConfig::hook_ntqip,
         "fake DebugPort/DebugObjectHandle/DebugFlags/... answers"},
        {"NtSetInformationThreadHook", &HideConfig::hook_ntsit,
         "swallow ThreadHideFromDebugger (thread stays debuggable)"},
        {"NtQuerySystemInformationHook", &HideConfig::hook_ntqsi,
         "fake SystemKernelDebuggerInformation and friends"},
        {"NtQueryObjectHook", &HideConfig::hook_ntqo, "hide DebugObject counts"},
        {"NtSetInformationProcessHook", &HideConfig::hook_ntsipr,
         "virtualize BreakOnTermination/DebugFlags/HandleTracing"},
        {"NtCloseHook", &HideConfig::hook_ntclose,
         "no exception when the target closes an invalid handle"},
        {"NtYieldExecutionHook", &HideConfig::hook_ntyield,
         "normalize NtYieldExecution (timing-based checks)"},
        {"NtGetContextThreadHook", &HideConfig::hook_ctx,
         "hide debug registers from GetThreadContext"},
        {"NtSetContextThreadHook", &HideConfig::hook_ctx,
         "keep debug register writes out of SetThreadContext"},
        {"FakeParentProcess", &HideConfig::fake_parent, "report explorer.exe as the parent process"},
    };
    return k;
}

bool hide_set_key(HideConfig& c, const std::string& key, bool value, std::string& err) {
    for (const auto& k : hide_keys()) {
        if (to_lower(key) == to_lower(k.key)) {
            c.*(k.field) = value;
            return true;
        }
    }
    err = "unknown hide switch: " + key;
    return false;
}

std::vector<std::string> hide_profile_names() {
    return {"off", "basic", "standard", "aggressive", "vmp", "themida", "obsidium"};
}

bool hide_profile_config(const std::string& name, HideConfig& out) {
    HideConfig c{};
    std::string n = to_lower(name);
    if (n == "off" || n == "disabled" || n == "none") {
        c = HideConfig{};
        c.peb_being_debugged = c.peb_nt_global_flag = c.peb_heap_flags = false;
        c.peb_startup_info = c.peb_os_build = c.kuser_debugger = false;
        c.hook_ntqip = c.hook_ntsit = c.hook_ntqsi = c.hook_ntqo = false;
        c.hook_ntsipr = c.hook_ntclose = c.hook_ntyield = c.hook_ctx = false;
        c.fake_parent = false;
    } else if (n == "basic") {
        // ScyllaHide's "Basic": PEB-level only, no hooks
        c.hook_ntqip = c.hook_ntsit = c.hook_ntqsi = c.hook_ntqo = false;
        c.hook_ntsipr = c.hook_ntclose = c.hook_ntyield = c.hook_ctx = false;
        c.fake_parent = false;
    } else if (n == "standard") {
        // common al-khaser checks minus the rarely used hooks
        c.hook_ntsipr = false;
        c.hook_ntyield = false;
    } else if (n == "aggressive") {
        // everything aidbg can do
    } else if (n == "vmp") {
        // ScyllaHide "VMProtect x86/x64"
        c.hook_ntqsi = c.hook_ntsipr = c.hook_ntyield = c.hook_ctx = false;
    } else if (n == "themida") {
        // ScyllaHide "Themida x86/x64" (its NtCreateThreadEx/NtUser* hooks have
        // no aidbg equivalent yet and are reported as unsupported)
        c.hook_ntqo = c.hook_ntsipr = c.hook_ntyield = c.hook_ctx = false;
    } else if (n == "obsidium") {
        // ScyllaHide "Obsidium x86/x64"
        c.hook_ntsit = c.hook_ntqo = c.hook_ntsipr = c.hook_ntyield = false;
        c.hook_ctx = false;
    } else {
        return false;
    }
    out = c;
    return true;
}

Json hide_config_json(const HideConfig& c) {
    Json j = Json::obj();
    for (const auto& k : hide_keys()) j.set_bool(k.key, c.*(k.field));
    return j;
}

Json hide_catalog_json() {
    Json j = Json::obj();
    Json profiles = Json::arr();
    for (const auto& name : hide_profile_names()) {
        HideConfig c;
        hide_profile_config(name, c);
        Json p = Json::obj();
        p.set_str("name", name);
        p.set("config", hide_config_json(c));
        profiles.push(std::move(p));
    }
    j.set("profiles", std::move(profiles));
    Json keys = Json::arr();
    for (const auto& k : hide_keys()) {
        Json e = Json::obj();
        e.set_str("key", k.key);
        e.set_str("help", k.help);
        keys.push(std::move(e));
    }
    j.set("switches", std::move(keys));
    // recognized but not implemented: honest list so configs fail loudly
    static const char* kUnsupported[] = {
        "DLLNormal", "DLLStealth", "DLLUnload", "GetLocalTimeHook", "GetSystemTimeHook",
        "GetTickCountHook", "GetTickCount64Hook", "GetSystemTimeHook", "NtQuerySystemTimeHook",
        "NtQueryPerformanceCounterHook", "OutputDebugStringHook", "NtContinueHook",
        "KiUserExceptionDispatcherHook", "NtCreateThreadExHook", "NtCreateThreadHook",
        "PreventThreadCreation", "RemoveDebugPrivileges", "KillAntiAttach",
        "NtUserBlockInputHook", "NtUserFindWindowExHook", "NtUserBuildHwndListHook",
        "NtUserQueryWindowHook", "NtUserGetForegroundWindowHook", "NtSetDebugFilterStateHook",
    };
    Json un = Json::arr();
    for (const char* s : kUnsupported) un.push(Json::s(s));
    j.set("unsupported", std::move(un));
    return j;
}

bool hide_load_ini(HideConfig& c, const std::string& path, Json& report, std::string& err) {
    std::ifstream f(to_wide(path));
    if (!f) {
        err = "cannot open " + path;
        return false;
    }
    std::map<std::string, std::map<std::string, std::string>> sections;
    std::string cur, line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.front() == '[' && line.back() == ']') {
            cur = to_lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        sections[cur][to_lower(key)] = val;
    }

    // section to use: explicit [hide] wins, then [SETTINGS] CurrentProfile,
    // then the first non-SETTINGS section
    std::string use;
    if (sections.count("hide")) {
        use = "hide";
    } else if (sections.count("settings") && sections["settings"].count("currentprofile")) {
        use = to_lower(sections["settings"]["currentprofile"]);
    }
    if (use.empty() || !sections.count(use)) {
        for (auto& kv : sections)
            if (kv.first != "settings") {
                use = kv.first;
                break;
            }
    }
    if (use.empty() || !sections.count(use)) {
        err = "no usable profile section in " + path;
        return false;
    }

    Json rep = Json::obj();
    rep.set_str("section", use);
    Json applied = Json::arr(), unsupported = Json::arr();
    for (const auto& kv : sections[use]) {
        std::string err2;
        bool v = kv.second == "1" || to_lower(kv.second) == "true";
        if (hide_set_key(c, kv.first, v, err2)) {
            applied.push(Json::s(kv.first));
        } else {
            unsupported.push(Json::s(kv.first));
        }
    }
    rep.set("applied", std::move(applied));
    rep.set("ignored", std::move(unsupported));
    report = std::move(rep);
    return true;
}

bool hide_save_ini(const HideConfig& c, const std::string& path, std::string& err) {
    std::ofstream f(to_wide(path), std::ios::trunc);
    if (!f) {
        err = "cannot write " + path;
        return false;
    }
    f << "[hide]\n";
    for (const auto& k : hide_keys()) f << k.key << "=" << (c.*(k.field) ? 1 : 0) << "\n";
    return true;
}

// ================================================================ hook sites

const char* hook_api_name(HookApi a) {
    switch (a) {
        case HookApi::NtQueryInformationProcess: return "NtQueryInformationProcess";
        case HookApi::NtSetInformationThread: return "NtSetInformationThread";
        case HookApi::NtQuerySystemInformation: return "NtQuerySystemInformation";
        case HookApi::NtQueryObject: return "NtQueryObject";
        case HookApi::NtSetInformationProcess: return "NtSetInformationProcess";
        case HookApi::NtClose: return "NtClose";
        case HookApi::NtYieldExecution: return "NtYieldExecution";
        case HookApi::NtGetContextThread: return "NtGetContextThread";
        case HookApi::NtSetContextThread: return "NtSetContextThread";
    }
    return "?";
}
const char* hook_api_export(HookApi a) {
    return hook_api_name(a);  // export name == api name for these
}
int hook_api_count() { return 9; }

namespace {

bool api_enabled(const HideConfig& c, HookApi a) {
    switch (a) {
        case HookApi::NtQueryInformationProcess: return c.hook_ntqip;
        case HookApi::NtSetInformationThread: return c.hook_ntsit;
        case HookApi::NtQuerySystemInformation: return c.hook_ntqsi;
        case HookApi::NtQueryObject: return c.hook_ntqo;
        case HookApi::NtSetInformationProcess: return c.hook_ntsipr;
        case HookApi::NtClose: return c.hook_ntclose;
        case HookApi::NtYieldExecution: return c.hook_ntyield;
        case HookApi::NtGetContextThread:
        case HookApi::NtSetContextThread: return c.hook_ctx;
    }
    return false;
}

// reports an emulation failure with the exact stage (kept observable: a silent
// failure here once caused the target to execute half a syscall stub)
bool emit_fail(const HookSite& site, const char* stage) {
    Json d = Json::obj();
    d.set_str("api", hook_api_name((HookApi)site.api));
    d.set_hex("address", site.address);
    d.set_str("stage", stage);
    Output::instance().event("hide_emulate_failed", "hook emulation failed", d);
    return false;
}

// module bitness from its PE header (IMAGE_FILE_HEADER.Machine lives at
// e_lfanew + 4, not at base + 4)
bool module_is32(HANDLE proc, uint64_t base) {
    uint32_t lfanew = 0;
    if (!rd_bytes(proc, base + 0x3C, &lfanew, 4) || !lfanew || lfanew > 0x1000) return false;
    uint16_t machine = 0;
    if (!rd_bytes(proc, base + lfanew + 4, &machine, 2)) return false;
    return machine == 0x14C;
}

}  // namespace

ProcessHooks* Hider::hooks_for(uint32_t pid) {
    for (auto& p : procs_)
        if (p.pid == pid) return &p;
    return nullptr;
}

bool Hider::plant(ProcessHooks& ph, HANDLE proc, std::string& err) {
    // find every ntdll loaded into this process and put INT3 on the enabled
    // exports; a WOW64 process has both a 64-bit and a 32-bit ntdll and the
    // calling convention differs, so each site remembers its own bitness
    Engine* eng = eng_;
    std::vector<ModuleInfo> mods;
    for (const ProcessInfo& p : eng->processes())
        if (p.pid == ph.pid) {
            mods = p.modules;
            break;
        }
    size_t before = ph.sites.size();
    for (const auto& m : mods) {
        if (to_lower(m.name) != "ntdll.dll") continue;
        bool m32 = module_is32(proc, m.base);
        // hook only the ntdll that matches the target's own bitness: a WOW64
        // process keeps its API surface in the 32-bit ntdll, and mixing hook
        // modes inside one process would need per-site register contexts
        if (m32 != ph.is32) continue;
        Exports ex;
        ex.init(proc, m.base, m.name);
        std::string e;
        if (!ex.load(e)) continue;
        for (int ai = 0; ai < hook_api_count(); ++ai) {
            HookApi api = (HookApi)ai;
            if (!api_enabled(cfg_, api)) continue;
            std::vector<ExportEntry> hits = ex.enumerate(hook_api_export(api), 2);
            for (const auto& hit : hits) {
                if (hit.forwarder.size()) continue;
                uint64_t addr = hit.address;
                bool dup = false;
                for (const auto& s : ph.sites)
                    if (s.address == addr) dup = true;
                if (dup) continue;
                uint8_t orig = 0;
                if (!rd_bytes(proc, addr, &orig, 1)) continue;
                if (!wr_bytes(proc, addr, "\xCC", 1)) continue;
                flush_icache(proc, addr, 1);
                HookSite s;
                s.api = ai;
                s.address = addr;
                s.original = orig;
                s.planted = true;
                s.is32 = m32;
                ph.sites.push_back(s);
            }
        }
    }
    ph.planted = !ph.sites.empty();
    if (ph.sites.size() == before && before == 0) {
        err = "no ntdll exports hooked (ntdll not loaded yet?)";
        return false;
    }
    return true;
}

void Hider::unplant(ProcessHooks& ph, HANDLE proc) {
    for (auto& s : ph.sites) {
        if (!s.planted) continue;
        wr_bytes(proc, s.address, &s.original, 1);
        flush_icache(proc, s.address, 1);
        s.planted = false;
    }
}

// ============================================================== L1 patches

void Hider::apply_l1(uint32_t pid, HANDLE proc, bool is32, Json& report) {
    Json changes = Json::arr();
    auto touch = [&](const char* what, const std::string& detail) {
        Json j = Json::obj();
        j.set_str("patch", what);
        j.set_str("detail", detail);
        changes.push(std::move(j));
    };

    // a WOW64 process has two PEBs and both are checked by different tools
    for (int pass = 0; pass < (is32 ? 2 : 1); ++pass) {
        bool p32 = is32 && pass == 0;
        PebInfo peb;
        std::string e;
        if (!read_peb(proc, p32, peb, e)) continue;
        const Offsets& O = offs(p32);
        uint64_t base = peb.address;

        if (cfg_.peb_being_debugged) {
            if (wr_u8(proc, base + O.being_debugged, 0))
                touch(p32 ? "peb32.being_debugged" : "peb.being_debugged",
                      fmt("%s+0x%X = 0", hex8(base).c_str(), O.being_debugged));
        }
        if (cfg_.peb_nt_global_flag) {
            uint32_t v = rd_u32(proc, base + O.nt_global_flag);
            if (v & kNtGlobalFlagDebugBits) {
                uint32_t nv = v & ~kNtGlobalFlagDebugBits;
                if (wr_u32(proc, base + O.nt_global_flag, nv))
                    touch(p32 ? "peb32.nt_global_flag" : "peb.nt_global_flag",
                          fmt("0x%X -> 0x%X", v, nv));
            }
        }
        if (cfg_.peb_os_build) {
            uint64_t addr = base + O.os_build;
            uint16_t v = rd_u16(proc, addr);
            uint32_t real = current_os_build();
            // sanity: only patch when the field really holds a build number
            if (real && v == (uint16_t)real && real != 10000) {
                uint16_t nv = 10000;  // a fixed, non-instrumented looking value
                if (wr_bytes(proc, addr, &nv, 2))
                    touch(p32 ? "peb32.os_build" : "peb.os_build",
                          fmt("%u -> %u (kept plausible)", v, nv));
            }
        }
        if (cfg_.peb_startup_info) {
            uint64_t pp = peb.process_parameters;
            if (pp) {
                // StartingX..FillAttribute: 7 ULONGs of debugger-leaking
                // STARTUPINFO coordinates (classic StartupInfo check)
                uint8_t zero[28] = {0};
                if (wr_bytes(proc, pp + O.pp_starting_x, zero, sizeof(zero)))
                    touch(p32 ? "peb32.startupinfo" : "peb.startupinfo",
                          "zeroed StartingX..FillAttribute");
                uint32_t wf = kStartfUseShowWindow, sw = kSwShownormal;
                wr_bytes(proc, pp + O.pp_window_flags, &wf, 4);
                wr_bytes(proc, pp + O.pp_show_window_flags, &sw, 4);
                // hide an IFEO launch from the target
                uint32_t flags = rd_u32(proc, pp + O.pp_flags);
                if (!(flags & kImageKeyMissing)) {
                    wr_u32(proc, pp + O.pp_flags, flags | kImageKeyMissing);
                    touch(p32 ? "peb32.process_parameters.flags" : "peb.process_parameters.flags",
                          fmt("0x%X -> 0x%X (IMAGE_KEY_MISSING)", flags,
                              flags | kImageKeyMissing));
                }
            }
        }
        if (cfg_.peb_heap_flags) {
            uint32_t n = rd_u32(proc, base + O.num_heaps);
            uint32_t maxn = rd_u32(proc, base + O.max_heaps);
            uint64_t arr = rd_ptr(proc, base + O.heaps, p32);
            // sanity: NumberOfHeaps is small and never above the maximum
            if (arr && n >= 1 && n <= 64 && n <= maxn) {
                size_t changed = 0;
                for (uint32_t i = 0; i < n; ++i) {
                    uint64_t heap = rd_ptr(proc, arr + (p32 ? 4 : 8) * (uint64_t)i, p32);
                    if (!heap) continue;
                    uint32_t f = rd_u32(proc, heap + O.heap_flags);
                    uint32_t ff = rd_u32(proc, heap + O.heap_force_flags);
                    uint32_t nf = f & ~kHeapClearableFlags, nff = ff & ~kHeapClearableForceFlags;
                    if (nf != f) wr_u32(proc, heap + O.heap_flags, nf);
                    if (nff != ff) wr_u32(proc, heap + O.heap_force_flags, nff);
                    if (nf != f || nff != ff) ++changed;
                }
                if (changed)
                    touch(p32 ? "peb32.heap_flags" : "peb.heap_flags",
                          fmt("cleaned %zu heap(s) of %u", changed, n));
            }
        }
    }

    if (cfg_.kuser_debugger) {
        // KUSER_SHARED_DATA is shared but read-only; a write makes a private
        // copy visible to the target only
        uint8_t v = 0xFF;
        if (rd_bytes(proc, 0x7FFE02D4ull, &v, 1) && v != 0) {
            if (wr_u8(proc, 0x7FFE02D4ull, 0))
                touch("kuser.kd_debugger", fmt("0x%02X -> 0x00", v));
        }
    }

    (void)pid;
    report.set("patches", std::move(changes));
}

// ================================================================ L2 emulate

namespace {

struct FilterCtx {
    HANDLE proc;
    bool is32;
};

// DebugObject entries hide the debugger's debug objects. `zero_all` matches
// ScyllaHide's generic-vs-specific distinction (FilterObject's zeroTotal).
//
// The buffer was produced by a forwarded call in *this* process, so every
// TypeName.Buffer inside it points into our local copy. The caller expects
// pointers into its own buffer (buf_target): translate them in place, or the
// target dereferences a debugger address and crashes.
void filter_debug_objects(HANDLE proc, bool is32, uint8_t* buf, size_t len, uint64_t buf_target,
                          bool zero_all) {
    (void)proc;
    size_t ptr = is32 ? 4 : 8;
    if (len < 64) return;
    uint32_t count = 0;
    memcpy(&count, buf, 4);
    if (count == 0 || count > 128) return;
    // entries start pointer-aligned after NumberOfTypes
    size_t off = (sizeof(ULONG) + ptr - 1) & ~(ptr - 1);
    // sizeof(OBJECT_TYPE_INFORMATION): UNICODE_STRING + 13 ULONGs +
    // GENERIC_MAPPING + ULONG + 4 bytes + 3 ULONGs
    size_t struct_size = is32 ? 0x60 : 0x68;
    uint64_t local_base = (uint64_t)(uintptr_t)buf;
    for (uint32_t i = 0; i < count && off + struct_size <= len; ++i) {
        uint16_t name_len = 0, name_max = 0;
        memcpy(&name_len, buf + off, 2);
        memcpy(&name_max, buf + off + 2, 2);
        uint64_t name_ptr = 0;
        if (is32) {
            uint32_t p = 0;
            memcpy(&p, buf + off + 4, 4);
            name_ptr = p;
        } else {
            memcpy(&name_ptr, buf + off + 8, 8);
        }
        std::wstring name;
        if (name_ptr >= local_base && name_ptr + name_len <= local_base + len) {
            size_t noff = (size_t)(name_ptr - local_base);
            name.assign((wchar_t*)(buf + noff), name_len / 2);
            // relocate the pointer into the target's own buffer
            uint64_t fixed = buf_target + noff;
            if (is32) {
                uint32_t p32 = (uint32_t)fixed;
                memcpy(buf + off + 4, &p32, 4);
            } else {
                memcpy(buf + off + 8, &fixed, 8);
            }
        }
        if (name == L"DebugObject") {
            // TotalNumberOfObjects/TotalNumberOfHandles sit right after
            // the UNICODE_STRING
            size_t to = off + (is32 ? 8 : 16);
            uint32_t objs = 0, handles = 0;
            memcpy(&objs, buf + to, 4);
            memcpy(&handles, buf + to + 4, 4);
            objs = (zero_all || objs == 0) ? 0 : objs - 1;
            handles = (zero_all || handles == 0) ? 0 : handles - 1;
            memcpy(buf + to, &objs, 4);
            memcpy(buf + to + 4, &handles, 4);
        }
        // ScyllaHide's FilterObjects stride: struct + aligned name buffer
        size_t next = off + struct_size;
        next += (name_max + ptr - 1) / ptr * ptr;
        if (next <= off) break;
        off = next;
    }
}

}  // namespace

bool Hider::emulate(ProcessHooks& ph, HookSite& site, bool& stop) {
    resolve_ntdll();  // forwarding needs the debugger's own ntdll entry points
    Engine* eng = eng_;
    HANDLE proc = eng->process();
    // the calling convention follows the module the hook lives in: a WOW64
    // process runs 32-bit and 64-bit ntdll side by side
    const bool is32 = site.is32;
    HookApi api = (HookApi)site.api;

    CpuState st;
    std::string e;
    const char* fail_stage = "get_state";
    if (!eng->get_state(st, e)) return emit_fail(site, fail_stage);

    // rewind onto the original instruction: from here on the stack layout is
    // exactly what the caller prepared for the real function
    st.rip = site.address;
    fail_stage = "rewind";
    if (!eng->set_state(st, e)) return emit_fail(site, fail_stage);

    uint64_t a[6] = {0};
    fail_stage = "read_args";
    if (!read_args(proc, st, is32, api == HookApi::NtQueryInformationProcess ? 5 : 6, a)) {
        Json d = Json::obj();
        d.set_str("api", hook_api_name(api));
        d.set_hex("rip", st.rip);
        d.set_hex("rsp", st.gpr[4]);
        d.set_u("pid", (uint64_t)eng->pid());
        d.set_bool("proc_handle_valid", proc != nullptr);
        d.set_u("proc_pid", (uint64_t)GetProcessId(proc));
        d.set_u("thread_pid", (uint64_t)GetProcessIdOfThread(eng->thread()));
        d.set_bool("is32", is32);
        uint64_t probe_val = 0;
        std::string e2;
        d.set_bool("rsp_readable", read_memory(proc, st.gpr[4], &probe_val, 8, e2) ? true : false);
        e2.clear();
        d.set_bool("rsp28_readable",
                   read_memory(proc, st.gpr[4] + 0x28, &probe_val, 8, e2) ? true : false);
        d.set_str("err", e2);
        Output::instance().event("hide_read_args_failed", "cannot read call arguments", d);
        stop = true;
        return emit_fail(site, fail_stage);
    }
    fail_stage = "finish";

    bool finish_ok = true;
    auto done = [&](LONG status) {
        int nargs = 4;  // stdcall arity, matters for x86 stack cleanup
        switch (api) {
            case HookApi::NtClose: nargs = 1; break;
            case HookApi::NtYieldExecution: nargs = 0; break;
            case HookApi::NtGetContextThread:
            case HookApi::NtSetContextThread: nargs = 2; break;
            case HookApi::NtQueryInformationProcess:
            case HookApi::NtQueryObject: nargs = 5; break;
            default: nargs = 4; break;
        }
        if (!finish_call(eng, is32, nargs, (uint64_t)(int64_t)status)) finish_ok = false;
    };
    switch (api) {
        case HookApi::NtYieldExecution: {
            // al-khaser counts STATUS_NO_YIELD_PERFORMED answers; ScyllaHide
            // settles on STATUS_ACCESS_DENIED as the least detectable result
            done(kStatusAccessDenied);
            break;
        }
        case HookApi::NtSetInformationThread: {
            if ((ULONG)a[1] == kThreadHideFromDebugger && (ULONG)a[3] == 0) {
                done(kStatusSuccess);  // swallow: the thread stays debuggable
            } else {
                // let the real call run in the target's context
                unplant_for_step(ph, site);
                return true;
            }
            break;
        }
        case HookApi::NtSetInformationProcess: {
            ULONG cls = (ULONG)a[1];
            if (cls == kProcessBreakOnTermination || cls == kProcessDebugFlags ||
                cls == kProcessHandleTracing) {
                // record and accept: the target believes the setting stuck
                done(kStatusSuccess);
            } else {
                unplant_for_step(ph, site);
                return true;
            }
            break;
        }
        case HookApi::NtClose: {
            uint64_t hval = a[0];
            HANDLE local = dup_arg_handle(eng, hval, is32, false);
            if (!local) {
                // invalid handle: answering without the real call is what keeps
                // STATUS_INVALID_HANDLE from being raised (al-khaser's check)
                done(kStatusInvalidHandle);
                break;
            }
            // valid: check OBJ_PROTECT_FROM_CLOSE like ScyllaHide does
            struct {
                uint8_t inherit, protect;
            } flags = {0, 0};
            LONG qst = pNtQO ? pNtQO(local, kObjectHandleFlagInformation, &flags, sizeof(flags),
                                     nullptr)
                             : -1;
            if (qst >= 0 && flags.protect) {
                CloseHandle(local);
                done(kStatusHandleNotClosable);
                break;
            }
            CloseHandle(local);
            // close must happen in the target's handle table: replay the real
            // instruction under a single step
            unplant_for_step(ph, site);
            break;
        }
        case HookApi::NtQueryInformationProcess: {
            ULONG cls = (ULONG)a[1];
            uint64_t info = arg_ptr(is32, a[2]);
            ULONG len = (ULONG)a[3];
            uint64_t retlen_addr = arg_ptr(is32, a[4]);
            if (cls == kProcessDebugPort) {
                uint64_t zero = 0;
                wr_bytes(proc, info, &zero, is32 ? 4 : 8);
                if (retlen_addr) wr_u32(proc, retlen_addr, is32 ? 4 : 8);
                done(kStatusSuccess);
            } else if (cls == kProcessDebugObjectHandle) {
                uint64_t zero = 0;
                wr_bytes(proc, info, &zero, is32 ? 4 : 8);
                if (retlen_addr) wr_u32(proc, retlen_addr, is32 ? 4 : 8);
                done(kStatusPortNotSet);  // exactly what a non-debugged run sees
            } else if (cls == kProcessDebugFlags) {
                ULONG one = 1;  // PROCESS_DEBUG_INHERIT: "no debug inherit" clear
                if (info && len >= 4) wr_bytes(proc, info, &one, 4);
                if (retlen_addr) wr_u32(proc, retlen_addr, 4);
                done(kStatusSuccess);
            } else if (cls == kProcessBreakOnTermination) {
                ULONG zero = 0;
                if (info && len >= 4) wr_bytes(proc, info, &zero, 4);
                if (retlen_addr) wr_u32(proc, retlen_addr, 4);
                done(kStatusSuccess);
            } else if (cls == kProcessHandleTracing) {
                done(kStatusInvalidParameter);  // tracing is "not available"
            } else if (is32 && cls == kProcessBasicInformation) {
                // A WOW64 target must see the 32-bit PROCESS_BASIC_INFORMATION
                // (its PebBaseAddress is the PEB32). Forwarding the query from
                // this 64-bit debugger would return the 64-bit layout, which
                // the 32-bit caller reads as garbage and crashes on.
                uint8_t out[24] = {0};
                uint64_t peb32 = 0, parent = 0;
                int64_t affinity = 0;
                LONG prio = 8;
                if (pNtQIP) {
                    uint8_t b64[48] = {0};
                    if (pNtQIP(proc, kProcessBasicInformation, b64, sizeof(b64), nullptr) >= 0) {
                        affinity = (int64_t)*(uint64_t*)(b64 + 0x10);
                        prio = *(LONG*)(b64 + 0x18);
                        parent = *(uint64_t*)(b64 + 0x28);
                    }
                    uint8_t wb[8] = {0};
                    if (pNtQIP(proc, kProcessWow64Information, wb, sizeof(wb), nullptr) >= 0)
                        peb32 = (uint64_t)*(uint32_t*)wb;
                }
                if (cfg_.fake_parent && explorer_pid()) parent = explorer_pid();
                if (!peb32) {
                    // cannot fake a sane answer - let the real call run
                    unplant_for_step(ph, site);
                    return true;
                }
                LONG st_pending = 0x103;  // STATUS_PENDING while running
                memcpy(out + 0x00, &st_pending, 4);
                uint32_t v32 = (uint32_t)peb32;
                memcpy(out + 0x04, &v32, 4);
                v32 = (uint32_t)affinity;
                memcpy(out + 0x08, &v32, 4);
                memcpy(out + 0x0C, &prio, 4);
                v32 = (uint32_t)GetProcessId(proc);
                memcpy(out + 0x10, &v32, 4);
                v32 = (uint32_t)parent;
                memcpy(out + 0x14, &v32, 4);
                if (info && len >= 24) wr_bytes(proc, info, out, 24);
                if (retlen_addr) wr_u32(proc, retlen_addr, 24);
                done(kStatusSuccess);
            } else if (is32) {
                // any other class has an architecture dependent layout; let
                // the real 32-bit call run instead of forwarding a 64-bit one
                unplant_for_step(ph, site);
                return true;
            } else if (cls != kProcessBasicInformation && cls != kProcessIoCounters) {
                // other classes can return buffers with self-referential
                // pointers (image names etc.); replay the real call instead
                unplant_for_step(ph, site);
                return true;
            } else {
                // forward the real query through a duplicated handle: both
                // forwarded classes are plain value structs (48/24 bytes)
                HANDLE local = dup_arg_handle(eng, a[0], is32, false);
                if (!local || !pNtQIP || len > (1u << 20)) {
                    if (local) CloseHandle(local);
                    unplant_for_step(ph, site);
                    return true;
                }
                std::vector<uint8_t> buf(len ? len : 1);
                ULONG rl = 0;
                LONG stt = pNtQIP(local, cls, len ? buf.data() : nullptr, len, &rl);
                CloseHandle(local);
                if (stt >= 0 && len) {
                    if (cls == kProcessBasicInformation && cfg_.fake_parent) {
                        // ScyllaHide's FakeCurrentParentProcessId
                        uint32_t exp = explorer_pid();
                        if (exp) {
                            if (is32 && len >= 0x18)
                                memcpy(buf.data() + 0x14, &exp, 4);
                            else if (!is32 && len >= 0x30) {
                                uint64_t h = exp;
                                memcpy(buf.data() + 0x28, &h, 8);
                            }
                        }
                    }
                    if (cls == kProcessIoCounters && len >= 24) {
                        uint64_t one = 1;  // OtherOperationCount
                        memcpy(buf.data() + 8, &one, is32 ? 4 : 8);
                    }
                    wr_bytes(proc, info, buf.data(), (rl && rl <= len ? rl : len));
                }
                if (retlen_addr) wr_u32(proc, retlen_addr, rl);
                done(stt);
            }
            break;
        }
        case HookApi::NtQuerySystemInformation: {
            ULONG cls = (ULONG)a[0];
            uint64_t info = arg_ptr(is32, a[1]);
            ULONG len = (ULONG)a[2];
            uint64_t retlen_addr = arg_ptr(is32, a[3]);
            if (cls == kSystemKernelDebuggerInformation) {
                uint8_t out[2] = {0, 1};  // Enabled=FALSE, NotPresent=TRUE
                if (info && len >= 2) wr_bytes(proc, info, out, 2);
                if (retlen_addr) wr_u32(proc, retlen_addr, 2);
                done(kStatusSuccess);
            } else if (cls == kSystemKernelDebuggerInformationEx) {
                uint8_t out[3] = {0, 0, 0};  // Allowed/Enabled/Present all FALSE
                if (info && len >= 3) wr_bytes(proc, info, out, 3);
                if (retlen_addr) wr_u32(proc, retlen_addr, 3);
                done(kStatusSuccess);
            } else if (cls == kSystemKernelDebuggerFlags) {
                uint8_t zero = 0;
                if (info && len >= 1) wr_bytes(proc, info, &zero, 1);
                if (retlen_addr) wr_u32(proc, retlen_addr, 1);
                done(kStatusSuccess);
            } else if (cls == kSystemCodeIntegrityUnlockInformation) {
                std::vector<uint8_t> zero(len ? len : 36, 0);
                if (info && len) wr_bytes(proc, info, zero.data(), len);
                if (retlen_addr) wr_u32(proc, retlen_addr, len);
                done(kStatusSuccess);
            } else if (cls == kSystemCodeIntegrityInformation && pNtQSI && info && len >= 8) {
                std::vector<uint8_t> buf(len);
                ULONG rl = 0;
                LONG stt = pNtQSI(cls, buf.data(), len, &rl);
                if (stt >= 0) {
                    ULONG opts = 1;  // CODEINTEGRITY_OPTION_ENABLED
                    memcpy(buf.data() + 4, &opts, 4);
                    wr_bytes(proc, info, buf.data(), (rl && rl <= len ? rl : len));
                }
                if (retlen_addr) wr_u32(proc, retlen_addr, rl);
                done(stt);
            } else {
                // every remaining class either needs no hiding or returns
                // buffers with self-referential pointers (SystemProcessInformation
                // and friends); replay the real call - filtering those is not
                // implemented yet
                unplant_for_step(ph, site);
                return true;
            }
            break;
        }
        case HookApi::NtQueryObject: {
            if (is32) {
                // OBJECT_*INFORMATION layouts carry pointers; forwarding from
                // this 64-bit debugger cannot reproduce the 32-bit view, so
                // let the real call run unfiltered on WOW64 targets
                unplant_for_step(ph, site);
                return true;
            }
            ULONG cls = (ULONG)a[1];
            uint64_t info = arg_ptr(is32, a[2]);
            ULONG len = (ULONG)a[3];
            uint64_t retlen_addr = arg_ptr(is32, a[4]);
            HANDLE local = dup_arg_handle(eng, a[0], is32, false);
            if (!local || !pNtQO || len > (1u << 22)) {
                if (local) CloseHandle(local);
                unplant_for_step(ph, site);
                return true;
            }
            std::vector<uint8_t> buf(len ? len : 1);
            ULONG rl = 0;
            LONG stt = pNtQO(local, cls, len ? buf.data() : nullptr, len, &rl);
            CloseHandle(local);
            if (stt >= 0 && len && cls == kObjectTypesInformation) {
                filter_debug_objects(proc, is32, buf.data(), (rl && rl <= len ? rl : len), info, true);
                wr_bytes(proc, info, buf.data(), (rl && rl <= len ? rl : len));
            } else if (stt >= 0 && len && cls == kObjectTypeInformation) {
                // single OBJECT_TYPE_INFORMATION: relocate its TypeName pointer
                // the same way and zero DebugObject counts
                size_t used = (rl && rl <= len ? rl : len);
                uint16_t name_len = 0;
                if (used >= 16) {
                    memcpy(&name_len, buf.data(), 2);
                    uint64_t name_ptr = 0, local_base = (uint64_t)(uintptr_t)buf.data();
                    if (is32) {
                        uint32_t p = 0;
                        memcpy(&p, buf.data() + 4, 4);
                        name_ptr = p;
                    } else {
                        memcpy(&name_ptr, buf.data() + 8, 8);
                    }
                    std::wstring name;
                    if (name_ptr >= local_base && name_ptr + name_len <= local_base + used) {
                        size_t noff = (size_t)(name_ptr - local_base);
                        name.assign((wchar_t*)(buf.data() + noff), name_len / 2);
                        uint64_t fixed = info + noff;
                        if (is32) {
                            uint32_t p32 = (uint32_t)fixed;
                            memcpy(buf.data() + 4, &p32, 4);
                        } else {
                            memcpy(buf.data() + 8, &fixed, 8);
                        }
                    }
                    if (name == L"DebugObject") {
                        size_t to = is32 ? 8 : 16;
                        uint32_t zero = 0;
                        memcpy(buf.data() + to, &zero, 4);
                        memcpy(buf.data() + to + 4, &zero, 4);
                    }
                }
                wr_bytes(proc, info, buf.data(), used);
            } else if (stt >= 0 && len) {
                wr_bytes(proc, info, buf.data(), (rl && rl <= len ? rl : len));
            }
            if (retlen_addr) wr_u32(proc, retlen_addr, rl);
            done(stt);
            break;
        }
        case HookApi::NtGetContextThread: {
            if (!cfg_.hook_ctx) {
                unplant_for_step(ph, site);
                return true;
            }
            HANDLE local = dup_arg_handle(eng, a[0], is32, true);
            uint64_t ctx = arg_ptr(is32, a[1]);
            if (!local || !ctx) {
                if (local) CloseHandle(local);
                unplant_for_step(ph, site);
                return true;
            }
            // Take the context from the debugger side (the exact struct the
            // caller expects) and blank the debug registers - this hides the
            // debugger's hardware breakpoints exactly like ScyllaHide does.
            ULONG ctxflags = 0;
            rd_bytes(proc, ctx, &ctxflags, 4);
            LONG stt = kStatusSuccess;
            if (is32) {
                WOW64_CONTEXT wc;
                memset(&wc, 0, sizeof(wc));
                wc.ContextFlags = ctxflags & ~0x10u;  // without DEBUG_REGISTERS
                if (Wow64GetThreadContext(local, &wc)) {
                    wc.ContextFlags = ctxflags;
                    wc.Dr0 = wc.Dr1 = wc.Dr2 = wc.Dr3 = wc.Dr6 = wc.Dr7 = 0;
                    wr_bytes(proc, ctx, &wc, sizeof(wc));
                } else {
                    stt = kStatusInvalidHandle;
                }
            } else {
                CONTEXT c;
                memset(&c, 0, sizeof(c));
                c.ContextFlags = ctxflags & ~0x10u;  // without DEBUG_REGISTERS
                if (GetThreadContext(local, &c)) {
                    c.ContextFlags = ctxflags;
                    c.Dr0 = c.Dr1 = c.Dr2 = c.Dr3 = 0;
                    c.Dr6 = c.Dr7 = 0;
                    c.LastBranchToRip = c.LastBranchFromRip = 0;
                    c.LastExceptionToRip = c.LastExceptionFromRip = 0;
                    wr_bytes(proc, ctx, &c, sizeof(c));
                } else {
                    stt = kStatusInvalidHandle;
                }
            }
            CloseHandle(local);
            done(stt);
            break;
        }
        case HookApi::NtSetContextThread: {
            if (!cfg_.hook_ctx) {
                unplant_for_step(ph, site);
                return true;
            }
            uint64_t ctx = arg_ptr(is32, a[1]);
            if (!ctx) {
                done(kStatusAccessViolation);
                break;
            }
            // strip CONTEXT_DEBUG_REGISTERS from the flags in the target's own
            // buffer (ScyllaHide's protection), then let the real call happen
            ULONG ctxflags = 0;
            if (rd_bytes(proc, ctx, &ctxflags, 4)) {
                ULONG cleared = ctxflags & ~0x10u;
                if (cleared != ctxflags) wr_bytes(proc, ctx, &cleared, 4);
            }
            unplant_for_step(ph, site);
            break;
        }
    }
    stop = false;
    if (!finish_ok) return emit_fail(site, "finish");
    return true;
}

// --------------------------------------------- pass-through (step + replant)

void Hider::unplant_for_step(ProcessHooks& ph, HookSite& site) {
    Engine* eng = eng_;
    HANDLE proc = eng->process();
    wr_bytes(proc, site.address, &site.original, 1);
    flush_icache(proc, site.address, 1);
    site.planted = false;
    pass_[eng_->tid()] = PassThrough{site.address, ph.pid};
    // single step over the real instruction, then re-plant the INT3
    CpuState st;
    std::string e;
    if (eng->get_state(st, e)) {
        st.rip = site.address;
        st.rflags |= 0x100;  // TF
        eng->set_state(st, e);
    }
}

// ================================================================== lifecycle

void Hider::on_process(uint32_t pid, HANDLE proc, bool is32) {
    if (hooks_for(pid)) return;
    ProcessHooks ph;
    ph.pid = pid;
    ph.is32 = is32;
    procs_.push_back(ph);
    if (!enabled_) return;
    Json rep = Json::obj();
    apply_l1(pid, proc, is32, rep);
    std::string e;
    plant(procs_.back(), proc, e);
}

void Hider::on_module_loaded(uint32_t pid, HANDLE proc, bool is32, const std::string& module) {
    if (!enabled_) return;
    ProcessHooks* ph = hooks_for(pid);
    if (!ph) {
        on_process(pid, proc, is32);
        ph = hooks_for(pid);
    }
    if (!ph || ph->planted) return;
    if (to_lower(module) != "ntdll.dll") return;
    std::string e;
    plant(*ph, proc, e);
}

void Hider::on_process_exit(uint32_t pid) {
    for (size_t i = 0; i < procs_.size(); ++i) {
        if (procs_[i].pid == pid) {
            procs_.erase(procs_.begin() + (long)i);
            break;
        }
    }
    for (auto it = pass_.begin(); it != pass_.end();) {
        if (it->second.pid == pid)
            it = pass_.erase(it);
        else
            ++it;
    }
}

void Hider::unplant_all() {
    Engine* eng = eng_;
    if (!eng) return;
    for (ProcessInfo& p : eng->processes()) {
        ProcessHooks* ph = hooks_for(p.pid);
        if (!ph) continue;
        unplant(*ph, p.handle);
        ph->sites.clear();
        ph->planted = false;
    }
    pass_.clear();
}

void Hider::reapply() {
    Engine* eng = eng_;
    if (!eng) return;
    for (ProcessInfo& p : eng->processes()) {
        if (!p.alive) continue;
        Json rep = Json::obj();
        if (enabled_) {
            apply_l1(p.pid, p.handle, p.is32, rep);
            ProcessHooks* ph = hooks_for(p.pid);
            if (!ph) {
                on_process(p.pid, p.handle, p.is32);
            } else if (!ph->planted) {
                std::string e;
                plant(*ph, p.handle, e);
            }
        }
    }
}

void Hider::apply_config(const HideConfig& c, const std::string& name) {
    cfg_ = c;
    profile_ = name;
    // re-plant / unplant around the new switch set
    Engine* eng = eng_;
    if (!eng) return;
    for (ProcessInfo& p : eng->processes()) {
        if (!p.alive) continue;
        ProcessHooks* ph = hooks_for(p.pid);
        if (!ph) continue;
        unplant(*ph, p.handle);
        ph->sites.clear();
        ph->planted = false;
        if (enabled_) {
            std::string e;
            plant(*ph, p.handle, e);
        }
    }
    if (enabled_) reapply();
}

void Hider::set_enabled(bool on) {
    if (on == enabled_) {
        if (on) reapply();
        return;
    }
    enabled_ = on;
    Engine* eng = eng_;
    if (!eng) return;
    for (ProcessInfo& p : eng->processes()) {
        if (!p.alive) continue;
        ProcessHooks* ph = hooks_for(p.pid);
        if (!ph) continue;
        if (!on) {
            unplant(*ph, p.handle);
            ph->sites.clear();
            ph->planted = false;
        }
    }
    if (on) reapply();
}

// ============================================================== event hooks

bool Hider::on_breakpoint(uint64_t addr, bool& stop) {
    if (!enabled_) return false;
    Engine* eng = eng_;
    ProcessHooks* ph = hooks_for(eng->pid());
    if (!ph) return false;
    for (auto& s : ph->sites) {
        if (s.address != addr || !s.planted) continue;
        s.hits++;
        bool ok = emulate(*ph, s, stop);
        if (!ok) {
            // Never leave the target in the middle of a stub: replay the
            // original instruction instead and keep the session running.
            Json d = Json::obj();
            d.set_str("api", hook_api_name((HookApi)s.api));
            d.set_hex("address", addr);
            Output::instance().event("hide_emulate_failed",
                                     "hook emulation failed, replaying the original call", d);
            unplant_for_step(*ph, s);
            stop = false;
        }
        return true;
    }
    return false;
}

bool Hider::on_single_step() {
    Engine* eng = eng_;
    auto it = pass_.find(eng ? eng->tid() : 0);
    if (it == pass_.end()) return false;  // not ours: a normal single step
    uint32_t pid = it->second.pid;
    uint64_t addr = it->second.addr;
    pass_.erase(it);
    ProcessHooks* ph = hooks_for(pid);
    if (!ph) return true;
    HANDLE proc = nullptr;
    for (const ProcessInfo& p : eng->processes())
        if (p.pid == pid) {
            proc = p.handle;
            break;
        }
    if (!proc) return true;
    for (auto& s : ph->sites) {
        if (s.address != addr) continue;
        wr_bytes(proc, s.address, "\xCC", 1);
        flush_icache(proc, s.address, 1);
        s.planted = true;
        break;
    }
    return true;
}

// ================================================================== reports

Json Hider::status_json() const {
    Json j = Json::obj();
    j.set_bool("enabled", enabled_);
    j.set_str("profile", profile_);
    j.set("config", hide_config_json(cfg_));
    size_t sites = 0, planted = 0;
    for (const auto& p : procs_) {
        sites += p.sites.size();
        for (const auto& s : p.sites)
            if (s.planted) planted++;
    }
    j.set_u("hook_sites", sites);
    j.set_u("hook_sites_planted", planted);
    return j;
}

Json Hider::hooks_json() const {
    Json arr = Json::arr();
    for (const auto& p : procs_) {
        for (const auto& s : p.sites) {
            Json j = Json::obj();
            j.set_u("pid", p.pid);
            j.set_str("api", hook_api_name((HookApi)s.api));
            j.set_hex("address", s.address);
            j.set_bool("planted", s.planted);
            j.set_u("hits", s.hits);
            arr.push(std::move(j));
        }
    }
    return arr;
}

// ================================================================== detect

Json Hider::detect_json(std::string& text) {
    resolve_ntdll();
    Engine* eng = eng_;
    HANDLE proc = eng->process();
    const bool is32 = eng->is32();

    Json checks = Json::arr();
    size_t exposed = 0, clean = 0, skipped = 0;
    auto add = [&](const char* name, const char* category, const char* status,
                   const std::string& value, const std::string& detail, const char* fix) {
        Json j = Json::obj();
        j.set_str("check", name);
        j.set_str("category", category);
        j.set_str("status", status);
        j.set_str("value", value);
        j.set_str("detail", detail);
        if (fix && *fix) j.set_str("fix", fix);
        checks.push(std::move(j));
        if (strcmp(status, "exposed") == 0)
            exposed++;
        else if (strcmp(status, "clean") == 0)
            clean++;
        else
            skipped++;
    };

    // ---- PEB level (IsDebuggerPresent / NtGlobalFlag family) ----
    for (int pass = 0; pass < (is32 ? 2 : 1); ++pass) {
        bool p32 = is32 && pass == 0;
        PebInfo peb;
        std::string e;
        if (!read_peb(proc, p32, peb, e)) continue;
        const Offsets& O = offs(p32);
        std::string tag = p32 ? "peb32" : "peb";
        add((tag + ".being_debugged").c_str(), "peb", peb.being_debugged ? "exposed" : "clean",
            fmt("%u", peb.being_debugged),
            fmt("PEB at %s (BeingDebugged)", hex8(peb.address).c_str()), "PebBeingDebugged");
        uint32_t ngf = rd_u32(proc, peb.address + O.nt_global_flag);
        bool ngf_bad = (ngf & kNtGlobalFlagDebugBits) != 0;
        add((tag + ".nt_global_flag").c_str(), "peb", ngf_bad ? "exposed" : "clean",
            fmt("0x%X", ngf), "FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS (0x70)",
            "PebNtGlobalFlag");

        // heaps
        uint32_t n = rd_u32(proc, peb.address + O.num_heaps);
        uint32_t maxn = rd_u32(proc, peb.address + O.max_heaps);
        uint64_t arr = rd_ptr(proc, peb.address + O.heaps, p32);
        if (arr && n >= 1 && n <= 64 && n <= maxn) {
            uint32_t bad = 0;
            for (uint32_t i = 0; i < n; ++i) {
                uint64_t heap = rd_ptr(proc, arr + (p32 ? 4 : 8) * (uint64_t)i, p32);
                if (!heap) continue;
                uint32_t f = rd_u32(proc, heap + O.heap_flags);
                uint32_t ff = rd_u32(proc, heap + O.heap_force_flags);
                if ((f & kHeapClearableFlags) || (ff & kHeapClearableForceFlags)) bad++;
            }
            add((tag + ".heap_flags").c_str(), "heap", bad ? "exposed" : "clean",
                fmt("%u of %u heap(s) with debug flags", bad, n),
                "Heap.Flags/ForceFlags carry RTL debug bits", "PebHeapFlags");
        }

        // startup info leak
        uint64_t pp = peb.process_parameters;
        if (pp) {
            uint32_t sx = rd_u32(proc, pp + O.pp_starting_x);
            uint32_t wf = rd_u32(proc, pp + O.pp_window_flags);
            bool bad = sx != 0 || (wf != 0 && wf != kStartfUseShowWindow);
            add((tag + ".startupinfo").c_str(), "peb", bad ? "exposed" : "clean",
                fmt("StartingX=%u WindowFlags=0x%X", sx, wf),
                "debuggers leak non-zero STARTUPINFO coordinates", "PebStartupInfo");
        }
    }

    // ---- KUSER_SHARED_DATA ----
    {
        uint8_t v = 0xFF;
        if (rd_bytes(proc, 0x7FFE02D4ull, &v, 1)) {
            bool bad = v != 0;
            add("kuser.kd_debugger", "kernel", bad ? "exposed" : "clean", fmt("0x%02X", v),
                "KUSER_SHARED_DATA.KdDebuggerEnabled bit flags", "HookKuserSharedData");
        }
    }

    // ---- kernel-level queries the target can make ----
    // These read the *real* kernel state from the debugger side. When the
    // corresponding hook is planted the target gets the hidden answer instead,
    // so report the effective state and keep the real one visible.
    bool qip_hooked = cfg_.hook_ntqip;
    {
        bool any_site = false;
        for (const auto& ph : procs_)
            for (const auto& s : ph.sites)
                if (s.api == (int)HookApi::NtQueryInformationProcess && s.planted) any_site = true;
        qip_hooked = qip_hooked && any_site;
    }
    if (pNtQIP) {
        struct {
            uint64_t v;
        } out{};
        ULONG rl = 0;
        LONG st = pNtQIP(proc, kProcessDebugPort, &out, is32 ? 4 : 8, &rl);
        uint64_t port = is32 ? (uint32_t)out.v : out.v;
        bool real_bad = st >= 0 && port;
        add("process.debug_port", "process", (real_bad && !qip_hooked) ? "exposed" : "clean",
            fmt("0x%llX (status 0x%08lX)", (unsigned long long)port, (unsigned long)st),
            real_bad ? (qip_hooked ? "real: debugged, but the target's query is answered "
                                     "with 0 by the hook (direct syscalls would bypass it)"
                                   : "NtQueryInformationProcess(ProcessDebugPort)")
                     : "no debug port",
            qip_hooked ? "" : "NtQueryInformationProcessHook");
        out.v = 0;
        st = pNtQIP(proc, kProcessDebugObjectHandle, &out, is32 ? 4 : 8, &rl);
        bool obj_bad = st >= 0 && out.v != 0;
        add("process.debug_object_handle", "process", (obj_bad && !qip_hooked) ? "exposed" : "clean",
            fmt("0x%llX (status 0x%08lX)", (unsigned long long)out.v, (unsigned long)st),
            obj_bad ? (qip_hooked ? "real: debug object exists, hidden from the target by "
                                     "the hook (direct syscalls would bypass it)"
                                  : "NtQueryInformationProcess(ProcessDebugObjectHandle)")
                     : "no debug object",
            qip_hooked ? "" : "NtQueryInformationProcessHook");
        uint32_t flags = 0;
        st = pNtQIP(proc, kProcessDebugFlags, &flags, 4, &rl);
        // 0 = debug inheritance disabled -> being debugged
        bool flags_bad = st >= 0 && flags == 0;
        add("process.debug_flags", "process", flags_bad ? "exposed" : "clean",
            fmt("%u (status 0x%08lX)", flags, (unsigned long)st),
            "NtQueryInformationProcess(ProcessDebugFlags)", "NtQueryInformationProcessHook");
    }

    if (pNtQSI) {
        uint8_t kd[2] = {0xFF, 0xFF};
        ULONG rl = 0;
        LONG st = pNtQSI(kSystemKernelDebuggerInformation, kd, sizeof(kd), &rl);
        bool bad = st >= 0 && (kd[0] != 0 || kd[1] == 0);
        add("kernel.debugger", "kernel", st >= 0 ? (bad ? "exposed" : "clean") : "skipped",
            fmt("Enabled=%u NotPresent=%u (status 0x%08lX)", kd[0], kd[1], (unsigned long)st),
            "NtQuerySystemInformation(SystemKernelDebuggerInformation): only detects KD, "
            "a user-mode debugger does not set this",
            "NtQuerySystemInformationHook");
    }

    // ---- DebugObject type counts (NtQueryObject family) ----
    if (pNtQO) {
        ULONG need = 0;
        pNtQO(nullptr, kObjectTypesInformation, nullptr, 0, &need);
        if (need && need < (1u << 20)) {
            std::vector<uint8_t> buf(need + 64, 0);
            ULONG rl = 0;
            LONG st = pNtQO(nullptr, kObjectTypesInformation, buf.data(), (ULONG)buf.size(), &rl);
            uint32_t dbg_objs = 0;
            if (st >= 0) {
                size_t ptr = 8;  // this parse runs on our own x64 buffers
                uint32_t count = 0;
                memcpy(&count, buf.data(), 4);
                size_t off = (4 + ptr - 1) & ~(ptr - 1);
                for (uint32_t i = 0; i < count && off + 0x68 <= buf.size(); ++i) {
                    uint16_t name_len = 0, name_max = 0;
                    memcpy(&name_len, buf.data() + off, 2);
                    memcpy(&name_max, buf.data() + off + 2, 2);
                    uint64_t name_ptr = 0;
                    memcpy(&name_ptr, buf.data() + off + 8, 8);
                    std::wstring name;
                    if (name_ptr) name.assign((wchar_t*)(uintptr_t)name_ptr, name_len / 2);
                    if (name == L"DebugObject")
                        memcpy(&dbg_objs, buf.data() + off + 16, 4);
                    size_t next = off + 0x68 + (name_max + 7) / 8 * 8;
                    if (next <= off) break;
                    off = next;
                }
            }
            add("objects.debug_object", "objects", dbg_objs ? "exposed" : "clean",
                fmt("%u live DebugObject(s)", dbg_objs),
                "NtQueryObject(ObjectTypesInformation): a debugger creates one per debuggee",
                "NtQueryObjectHook");
        }
    }

    // ---- parent process (al-khaser ParentProcess) ----
    if (pNtQIP) {
        uint8_t buf[48] = {0};
        ULONG rl = 0;
        LONG st = pNtQIP(proc, kProcessBasicInformation, buf, sizeof(buf), &rl);
        if (st >= 0) {
            uint64_t parent = is32 ? *(uint32_t*)(buf + 0x14) : *(uint64_t*)(buf + 0x28);
            std::string pname = "?";
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        if ((uint64_t)pe.th32ProcessID == parent) {
                            pname = to_utf8(pe.szExeFile);
                            break;
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
            std::string low = to_lower(pname);
            bool bad = low != "explorer.exe" && low != "winlogon.exe" && low != "cmd.exe";
            bool faked = bad && qip_hooked && cfg_.fake_parent;
            add("parent.process", "process", (bad && !faked) ? "exposed" : "clean",
                fmt("%llu (%s)", (unsigned long long)parent, pname.c_str()),
                faked ? "real parent is the debugger, reported as explorer.exe to the target"
                      : "unexpected parent process hints at a debugger launch",
                faked ? "" : "FakeParentProcess");
        }
    }

    // ---- ntdll code integrity (detects ScyllaHide-style hooks too) ----
    {
        const ProcessInfo* pi = nullptr;
        for (const ProcessInfo& p : eng->processes())
            if (p.pid == eng->pid()) pi = &p;
        uint64_t ntdll_base = 0;
        if (pi) {
            for (const auto& m : pi->modules)
                if (to_lower(m.name) == "ntdll.dll" && module_is32(proc, m.base) == is32) {
                    ntdll_base = m.base;
                    break;
                }
        }
        if (ntdll_base) {
            Exports ex;
            ex.init(proc, ntdll_base, "ntdll.dll");
            std::string e;
            std::string found;
            if (ex.load(e)) {
                for (int ai = 0; ai < hook_api_count(); ++ai) {
                    std::vector<ExportEntry> hits = ex.enumerate(hook_api_export((HookApi)ai), 2);
                    for (const auto& h : hits) {
                        uint8_t pro[8] = {0};
                        if (!rd_bytes(proc, h.address, pro, sizeof(pro))) continue;
                        bool ours = false;
                        for (const auto& ph : procs_)
                            for (const auto& s : ph.sites)
                                if (s.address == h.address && s.planted) ours = true;
                        bool expected = is32 ? (pro[0] == 0xB8) : (pro[0] == 0x4C && pro[1] == 0x8B);
                        if (ours)
                            found += fmt("%s=aidbg-int3 ", hook_api_name((HookApi)ai));
                        else if (!expected)
                            found += fmt("%s=hooked ", hook_api_name((HookApi)ai));
                    }
                }
            }
            add("ntdll.integrity", "self", found.empty() ? "clean" : "exposed",
                found.empty() ? "prologues intact" : trim(found),
                "INT3/hook bytes in ntdll exports are visible to a code-integrity scan; "
                "aidbg's own L2 hooks show up here by design",
                "");
        }
    }

    // ---- debug registers / user breakpoints the target would see ----
    {
        CpuState st;
        std::string e;
        bool dr = false;
        if (eng->get_state(st, e))
            dr = st.dr[0] || st.dr[1] || st.dr[2] || st.dr[3];
        for (const auto& bp : eng->bps.all())
            if (bp.kind == BpKind::Hardware && bp.planted_anywhere()) dr = true;
        add("threads.debug_registers", "self", dr ? "exposed" : "clean",
            dr ? "DR0-DR3 in use" : "none",
            "hardware breakpoints are visible through GetThreadContext unless the "
            "NtGetContextThread hook hides them",
            "NtGetContextThreadHook");
    }

    // ---- checks that need code execution inside the target ----
    for (const char* name :
         {"CloseHandle(invalid)", "NtYieldExecution", "timing(RDTSC/GetTickCount)", "TrapFlag",
          "int 2D / int 3", "OutputDebugString", "WriteWatch", "PageGuard scan", "TLS callbacks",
          "UnhandledExceptionFilter"}) {
        Json j = Json::obj();
        j.set_str("check", name);
        j.set_str("category", "runtime");
        j.set_str("status", "skipped");
        j.set_str("value", "");
        j.set_str("detail", "needs code execution inside the target; run the check under aidbg "
                            "and watch for the exception/return value");
        checks.push(std::move(j));
        skipped++;
    }

    Json summary = Json::obj();
    summary.set_u("exposed", exposed);
    summary.set_u("clean", clean);
    summary.set_u("skipped", skipped);

    Json out = Json::obj();
    out.set("summary", summary);
    out.set("checks", std::move(checks));

    std::string t = fmt("detect: %zu exposed, %zu clean, %zu not checkable from outside\n",
                        exposed, clean, skipped);
    t += std::string(72, '-') + "\n";
    t += fmt("%-32s %-8s %s\n", "check", "status", "value");
    for (size_t i = 0; i < out.get("checks").size(); ++i) {
        const Json& c = out.get("checks").at(i);
        t += fmt("%-32s %-8s %s\n", c.get("check").as_str().c_str(),
                 c.get("status").as_str().c_str(), c.get("value").as_str().c_str());
    }
    text = t;
    return out;
}

}  // namespace aj
