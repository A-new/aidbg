#pragma once
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

class Engine;

// Anti-anti-debug (hiding) subsystem.
//
// Design, following the reference implementations in the workspace:
//   ScyllaHide - injected hook DLL + PEB/heap patches, ini + per-packer profiles
//   HyperHide  - kernel driver + user hooks (we stay user-mode only)
//   Themidie   - MinHook injection for Themida-specific checks
//   xdbg       - injected Detours proxy with a config-driven hook mask
//   al-khaser  - the catalogue of checks to defeat (and the source of `detect`)
//
// aidbg keeps a single executable and never injects code, so the hiding works
// in two layers instead:
//   L1  memory patches written from the debugger side (PEB, heaps, StartupInfo,
//       KUSER_SHARED_DATA) - zero side effects on the target's execution.
//   L2  API virtualization: INT3 planted on ntdll exports in the target, and
//       when the target calls one the debugger answers instead - either fully
//       emulated (fake return value / filtered output buffer) or forwarded to
//       the real API through a handle duplicated into the debugger. NtClose is
//       executed in the target itself via a step-over so its handle table is
//       respected.
// Known cost of L2 (documented, honest): the 0xCC bytes live in the target's
// ntdll and would be found by a code-integrity scan of ntdll. ScyllaHide is
// detectable the same way (its trampoline hooks also change ntdll code).

// ---- configuration switches -----------------------------------------------
//
// The key names are exactly ScyllaHide's scylla_hide.ini names for the switches
// we implement, so an existing ScyllaHide profile can be loaded as-is. Keys we
// recognize but cannot implement are reported instead of silently ignored.
struct HideConfig {
    // L1: memory patches
    bool peb_being_debugged = true;
    bool peb_nt_global_flag = true;
    bool peb_heap_flags = true;
    bool peb_startup_info = true;
    bool peb_os_build = true;
    bool kuser_debugger = true;

    // L2: API virtualization
    bool hook_ntqip = true;    // NtQueryInformationProcess
    bool hook_ntsit = true;    // NtSetInformationThread (ThreadHideFromDebugger)
    bool hook_ntqsi = true;    // NtQuerySystemInformation
    bool hook_ntqo = true;     // NtQueryObject (DebugObject counts)
    bool hook_ntsipr = true;   // NtSetInformationProcess
    bool hook_ntclose = true;  // NtClose (invalid-handle exception)
    bool hook_ntyield = true;  // NtYieldExecution
    bool hook_ctx = true;      // NtGet/SetContextThread (hide debug registers)
    bool fake_parent = true;   // report explorer.exe as the parent process
};

struct HideKey {
    const char* key;             // scylla_hide.ini spelling
    bool HideConfig::*field;
    const char* help;
};
const std::vector<HideKey>& hide_keys();
bool hide_set_key(HideConfig& c, const std::string& key, bool value, std::string& err);

// Built-in profiles. ScyllaHide profiles map 1:1 where we implement the keys;
// "basic"/"standard"/"aggressive" are aidbg's own ladder.
std::vector<std::string> hide_profile_names();
bool hide_profile_config(const std::string& name, HideConfig& out);
Json hide_catalog_json();  // profiles + switches, machine readable

// ini round-trip (ScyllaHide-compatible key names)
bool hide_load_ini(HideConfig& c, const std::string& path, Json& report, std::string& err);
bool hide_save_ini(const HideConfig& c, const std::string& path, std::string& err);

// ---- L2 hook sites --------------------------------------------------------

enum class HookApi {
    NtQueryInformationProcess = 0,
    NtSetInformationThread,
    NtQuerySystemInformation,
    NtQueryObject,
    NtSetInformationProcess,
    NtClose,
    NtYieldExecution,
    NtGetContextThread,
    NtSetContextThread,
};
const char* hook_api_name(HookApi a);
const char* hook_api_export(HookApi a);
int hook_api_count();

struct HookSite {
    int api = 0;  // HookApi
    uint64_t address = 0;
    uint8_t original = 0;
    bool planted = false;
    // calling convention of this site: a WOW64 process has both a 32-bit and a
    // 64-bit ntdll and which one fired decides the register/stack layout
    bool is32 = false;
    uint64_t hits = 0;
};

struct ProcessHooks {
    uint32_t pid = 0;
    bool is32 = false;
    bool planted = false;
    std::vector<HookSite> sites;
};

class Hider {
public:
    void bind(Engine* e) { eng_ = e; }

    const HideConfig& config() const { return cfg_; }
    HideConfig& config() { return cfg_; }
    // switches config (and profile name) and immediately re-applies to a live
    // target; `name` is only for display
    void apply_config(const HideConfig& c, const std::string& name);

    bool enabled() const { return enabled_; }
    void set_enabled(bool on);
    const std::string& profile() const { return profile_; }

    // ---- engine callbacks ----
    void on_process(uint32_t pid, HANDLE proc, bool is32);  // created or attached
    void on_module_loaded(uint32_t pid, HANDLE proc, bool is32, const std::string& module);
    void on_process_exit(uint32_t pid);
    void reapply();  // re-run L1 and re-plant hooks in every process
    void unplant_all();  // remove every hook byte (detach safety)
    void reset();        // forget all per-process state (session teardown)

    // ---- snapshot capture support ----
    // Lifts every planted hook byte of `pid` so a snapshot reads the real
    // instruction bytes (a captured 0xCC would come back as a stray
    // breakpoint). replant_after_capture() puts the lifted bytes back; a site
    // whose address a user breakpoint took over in the meantime stays lifted,
    // matching plant()'s "user breakpoint owns the byte" rule.
    void lift_for_capture(uint32_t pid);
    void replant_after_capture(uint32_t pid);

    // Returns true when the breakpoint belongs to the hiding subsystem and has
    // been fully handled (the target keeps running, `stop` is set false).
    bool on_breakpoint(uint64_t addr, bool& stop);
    // Returns true when the single step belongs to a pass-through hook replay.
    bool on_single_step();

    // ---- reports ----
    Json status_json() const;
    Json hooks_json() const;
    // al-khaser style self-check of the live target: which checks would fire.
    Json detect_json(std::string& text);

private:
    ProcessHooks* hooks_for(uint32_t pid);
    HANDLE proc_of(uint32_t pid) const;
    bool plant(ProcessHooks& ph, HANDLE proc, std::string& err);
    void unplant(ProcessHooks& ph, HANDLE proc);
    // restore the original byte and single step so the real instruction runs in
    // the target (used when the call cannot be emulated from outside). Returns
    // false when the byte or the thread state could not be restored; the
    // caller must then surface the exception instead of continuing.
    bool unplant_for_step(ProcessHooks& ph, HookSite& site);
    // one per-process L1 pass; `report` collects what was changed
    void apply_l1(uint32_t pid, HANDLE proc, bool is32, Json& report);
    bool emulate(ProcessHooks& ph, HookSite& site, bool& stop);

    Engine* eng_ = nullptr;
    HideConfig cfg_;
    std::string profile_ = "standard";
    bool enabled_ = true;
    std::vector<ProcessHooks> procs_;
    // addresses lifted by the current lift_for_capture()/replant pair
    std::vector<uint64_t> capture_lifted_;

    // pass-through bookkeeping (NtClose on a valid handle executes in place),
    // keyed by thread: concurrent hits on different threads must not share it
    struct PassThrough {
        uint64_t addr;
        uint32_t pid;
    };
    std::map<uint32_t, PassThrough> pass_;
};

}  // namespace aj
