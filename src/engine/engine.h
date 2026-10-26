#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "engine/breakpoints.h"
#include "engine/exceptions.h"
#include "engine/expr.h"
#include "engine/hide.h"
#include "engine/memory.h"
#include "engine/notes.h"
#include "engine/patch.h"
#include "engine/registers.h"
#include "engine/snapshot.h"
#include "engine/symbols.h"
#include "engine/types.h"
#include "output/output.h"

namespace aj {

// Fixed-base (ASLR-off) launch that never writes the target's own bytes.
//
// The DYNAMIC_BASE flag is what makes the kernel relocate the image, and the
// kernel reads it while creating the image section during CreateProcess. The
// file itself must not be modified, and Windows refuses to write, replace or
// delete a running image's file - so the launch swaps the file by *renaming*
// (which Windows allows even for running images): the original is renamed
// aside untouched, a patched copy takes the path for the CreateProcess call,
// and revert() renames the original back before the target can execute one
// instruction. The path the target sees - and hashes, in a self-check - holds
// exactly the original file again.
struct TransientPePatch {
    std::wstring target;  // the path the user asked to run
    std::wstring orig;    // original file, renamed aside (pristine)
    std::wstring staged;  // patched copy, renamed away after the launch
    bool patched = false; // the path currently holds the patched copy
    std::string err;

    bool clear_dynamic_base(const std::wstring& path);
    void revert();
    ~TransientPePatch() { revert(); }
};

struct ModuleInfo {
    uint64_t base = 0;
    uint64_t size = 0;
    uint64_t entry = 0;
    uint64_t preferred_base = 0;  // ImageBase from the PE header
    std::string name;   // file name
    std::string path;   // full path

    bool relocated() const {
        return preferred_base != 0 && base != preferred_base;
    }
    uint64_t slide() const {
        return preferred_base ? (uint64_t)(base - preferred_base) : 0;
    }
};

struct ThreadInfo {
    uint32_t tid = 0;
    HANDLE handle = nullptr;
    uint64_t entry = 0;
    bool alive = true;
};

// One debuggee process. With child-process following enabled there can be
// several alive at once, so every per-process fact lives here rather than in
// the Engine.
struct ProcessInfo {
    uint32_t pid = 0;
    HANDLE handle = nullptr;
    bool is32 = false;
    uint64_t entry = 0;
    bool alive = true;
    bool is_child = false;          // spawned by the debuggee, not launched by us
    bool is_system = false;         // console host / other OS helper, not the target
    int startup_breaks_skipped = 0; // loader breakpoints walked past so far
    std::string exe_name;
    std::string exe_path;
    std::vector<ModuleInfo> modules;
    std::vector<ThreadInfo> threads;

    const char* arch_text() const { return is32 ? "x86" : "x64"; }
    size_t pointer_size() const { return is32 ? 4 : 8; }
};

enum class StopReason {
    None, Entry, Breakpoint, Step, Exception, GuardBreak, Exit, SystemBreak, Timeout,
    ModuleLoad
};

std::string stop_reason_text(StopReason r);

struct StopInfo {
    StopReason reason = StopReason::None;
    std::string text;
    uint32_t code = 0;          // exception code when relevant
    bool first_chance = true;
    uint64_t address = 0;       // breakpoint / fault address
    int bp_id = 0;
    uint32_t exit_code = 0;
    Json to_json() const;
};

enum class ResumeAction { Continue, StepInto, StepOver, StepOut, RunUntil };

class Engine {
public:
    Engine();
    ~Engine();

    // ---- session ----
    // follow_children: also debug processes spawned by the target.
    // fixed_base: disable ASLR for the target so the main image loads at its
    // PE ImageBase (0x140000000 for x64, 0x400000 for x86), matching what a
    // static disassembler shows.
    bool launch(const std::string& exe, const std::string& args, const std::string& cwd,
                bool new_console, bool follow_children, bool fixed_base, std::string& err);
    bool attach(uint32_t pid, std::string& err);
    bool detach(std::string& err);
    bool kill(std::string& err);

    // DLL targets: a DLL cannot be created as a process, so launch() runs it
    // inside a small host stub extracted from aidbg's own resources (the stub
    // loads the DLL and optionally calls one export). `args` then means
    // "[export]". Fixed-base applies to the DLL itself and stays in effect
    // until the loader maps it.
    static bool is_dll_image(const std::wstring& path);

    // OS helpers (conhost.exe) are debugged because DEBUG_PROCESS makes them
    // inherit the debug object, but they are not part of the user's session.
    bool active() const {
        for (const auto& p : processes_)
            if (p.alive && !p.is_system) return true;
        return false;
    }
    bool has_pending() const { return has_pending_; }
    bool is_paused() const { return active() && has_pending_; }

    // ---- execution control ----
    bool resume(ResumeAction act, uint64_t until_addr, uint32_t timeout_ms, std::string& err);
    // Injects a break into the target (DebugBreakProcess). Only queues the
    // event; the caller still has to pump the debug loop to reach the stop.
    bool interrupt(std::string& err);
    // interrupt() + wait for the resulting stop. This is the way back from a
    // `continue <timeout>` that timed out while the target kept running.
    bool pause(uint32_t timeout_ms, std::string& err);

private:
    bool resume_inner(ResumeAction act, uint64_t until_addr, uint32_t timeout_ms,
                      std::string& err);
    void maybe_auto_snapshot();

public:

    // ---- state access (these all act on the *current* process) ----
    SessionMeta session_meta() const;
    uint32_t pid() const { return current_pid_; }
    uint32_t tid() const { return current_tid_; }
    void set_tid(uint32_t tid);
    HANDLE process() const;
    HANDLE thread() const { return thread_handle_; }

    bool get_state(CpuState& out, std::string& err);
    bool set_state(const CpuState& st, std::string& err);

    // The debugger is always 64-bit; a session can mix x64 and WOW64 (x86)
    // targets, so the bitness belongs to each process, not to the session.
    bool is32() const;
    size_t pointer_size() const;
    const char* arch_text() const;

    std::vector<ModuleInfo>& modules();
    std::vector<ThreadInfo>& threads();

    // every process taking part in this debug session
    std::vector<ProcessInfo>& processes() { return processes_; }
    const std::vector<ProcessInfo>& processes() const { return processes_; }
    bool set_current_process(uint32_t pid, std::string& err);

    const ModuleInfo* module_at(uint64_t addr) const;
    const ModuleInfo* module_by_name(const std::string& name) const;

    // ---- analysis helpers ----
    // Resolves a number, register, "module+0xoff", "module!sym", or full expression.
    bool eval(const std::string& text, uint64_t& out, std::string& err);
    EvalContext eval_context();

    // stack walk -> array of frames (addr, symbol, module, line)
    Json callstack(size_t max_frames);
    bool return_address(uint64_t& out, std::string& err);

    // ---- breakpoint hooks used by commands ----
    // Applies hardware and guard-page bookkeeping for a newly added breakpoint.
    bool apply_breakpoint(Breakpoint& bp, std::string& err);
    bool remove_breakpoint(int id, std::string& err);
    bool set_breakpoint_enabled(int id, bool enabled, std::string& err);

    // On-hit commands (borrowed from Syser's BREAK_POINT::Command): the hook is
    // invoked with the breakpoint's command text at every hit, while the target
    // is paused and before the stop/continue decision is made. Execution
    // control from inside such a command would re-enter the event pump, so it
    // is refused (see resume/detach/kill).
    void set_command_hook(std::function<void(const std::string&)> hook) {
        command_hook_ = std::move(hook);
    }

    // Module-load breakpoints: stop when a module matching the pattern loads
    // ("bpload dbghelp.dll", '*' wildcards allowed).
    bool add_module_break(const std::string& pattern, std::string& err);
    bool del_module_break(const std::string& pattern, std::string& err);
    void clear_module_breaks() { module_breaks_.clear(); }
    const std::vector<std::string>& module_breaks() const { return module_breaks_; }

    Breakpoints bps;
    ExceptionPolicy policy;
    Symbols sym;
    Types types;
    // anti-anti-debug: PEB patches + ntdll API virtualization
    Hider hide;
    // user labels / comments anchored to module+RVA
    Notes notes;
    // recorded byte edits in module memory (patch tracking)
    PatchMgr patches;

    // Typed evaluation of `base(.field|->field|[index])*`, e.g.
    // `list.head->value`. Falls back to plain evaluation when no type matches.
    bool typed_eval(const std::string& expr, TypedValue& out, std::string& err);

    // ---- byte-exact memory reads (dump / snapshot capture) ----
    // Lifts/replants every INT3 of `pid` around a byte-exact read of its
    // memory (used by snapshot capture and by dump). replant_int3() restores
    // what lift_int3() removed.
    void lift_int3(uint32_t pid);
    void replant_int3(uint32_t pid);

    // ---- snapshots / reverse execution ----
    bool snapshot_save(const std::string& name, std::string& err);
    bool snapshot_restore(const std::string& name, std::string& err);
    // Same restore discipline (lift/replant breakpoints, park on the restored
    // RIP) but the pages come from the durable store instead of memory.
    bool snapshot_restore_from_store(uint32_t id, std::string& err);
    Snapshots snaps;

    // ---- import call tracing ----
    // Executes the call at `from_addr` under single step and reports which
    // module!function control actually reaches. This is what static analysis
    // cannot do: VMProtect/Themida route imports through opaque dispatchers
    // that only resolve at runtime. The target is put back afterwards.
    bool trace_import(uint64_t from_addr, size_t max_steps, Json& report, std::string& err);

    StopInfo stop_info() const { return stop_; }
    uint32_t exit_code() const { return exit_code_; }

private:
    bool wait_for_stop(uint32_t timeout_ms, std::string& err);
    void process_event(DEBUG_EVENT& ev, bool& stop, DWORD& continue_status);
    void continue_pending(DWORD status);
    bool resume_wait(uint32_t timeout_ms, std::string& err);

    bool single_step(std::string& err);
    bool single_step_replant(std::string& err);
    void replant_if_pending();
    bool set_trap_flag(bool enable, std::string& err);

    void on_create_process(DEBUG_EVENT& ev);
    // maps a fixed-base swap's staged file name ("app.exe.aidbg-patched-...")
    // back to the path the user launched; module lists, notes and patches
    // must all see the real file
    void normalize_swap_path(std::string& path) const;
    void on_exit_process(DEBUG_EVENT& ev);
    void on_load_dll(DEBUG_EVENT& ev, bool& stop);
    void on_unload_dll(DEBUG_EVENT& ev);
    void on_create_thread(DEBUG_EVENT& ev);
    void on_exit_thread(DEBUG_EVENT& ev);
    void on_exception(DEBUG_EVENT& ev, bool& stop, DWORD& continue_status);

    bool handle_software_breakpoint(uint64_t addr, Breakpoint* bp, bool& stop);
    // Returns true when a matching breakpoint was found (whether or not it
    // stopped the session); false means the DR6 bit belongs to no live bp.
    bool handle_hardware_breakpoint(uint32_t tid, uint32_t dr6, bool& stop);
    // A guard-page exception. `access_kind` is ExceptionInformation[0]
    // (0 = read, 1 = write, 8 = execute). Returns true when the exception
    // comes from one of our armed guard regions - whether it stopped the
    // session (`stop`) or is being stepped past silently with the guard
    // re-armed afterwards. False means the target installed the guard page
    // itself and the exception belongs to it.
    bool handle_guard_breakpoint(uint64_t access_addr, uint32_t access_kind, bool& stop);
    bool evaluate_condition(Breakpoint& bp, bool& should_stop, std::string& err);

    bool plant_all_hardware(std::string& err);
    bool arm_guard(Breakpoint& bp, uint32_t pid, std::string& err, uint64_t addr = 0);
    bool disarm_guard(Breakpoint& bp, uint32_t pid);

    void resolve_deferred_breakpoints();
    void refresh_threads();

    // Tears the session down: unplants hooks/breakpoints, closes handles,
    // clears per-session state and releases a pending debug event. The
    // breakpoint definitions survive so `restart` still has them.
    void reset_session();
    bool any_live_target() const;
    // Snapshot capture must read the real instruction bytes: every planted
    // INT3 (user software breakpoints and the hider's ntdll hooks) is lifted
    // for the read and put back afterwards, or a restored 0xCC whose
    // breakpoint no longer exists would surface as a stray exception. The
    // same discipline applies to `dump` - a dumped image carrying a planted
    // INT3 crashes as soon as it runs.
    bool capture_clean(const CpuState& st, const std::string& name, std::string& err);
    // Re-arms every kind of breakpoint after a snapshot overwrote the
    // process's memory, and parks on a breakpoint at the restored RIP.
    void finish_snapshot_restore(uint32_t rpid);
    // Address of `bp` in `p` (symbol breakpoints may resolve differently per
    // process because private modules can load at different bases).
    static uint64_t bp_address_for(const Breakpoint& bp, const ProcessInfo& p);

    // process lookup helpers
    ProcessInfo* proc_by_pid(uint32_t pid);
    ProcessInfo* cur_proc();
    const ProcessInfo* cur_proc() const;
    void sync_thread_handle();
    void pick_live_process();

    // world-stop: while the session is stopped on one process, every thread
    // of every other debuggee is suspended so agent-side inspection between
    // commands sees a stable world. Balanced with the resume in
    // continue_pending(); SuspendThread/ResumeThread are counted, so this is
    // safe even where the debug machinery already holds a thread.
    void freeze_world();
    void thaw_world();
    bool world_frozen_ = false;

    // state
    std::vector<ProcessInfo> processes_;
    uint32_t current_pid_ = 0;
    uint32_t current_tid_ = 0;
    HANDLE thread_handle_ = nullptr;  // handle of the current thread
    // DLL target support: extracted host stub and the still-active base swap
    std::wstring dll_host_stub_;
    TransientPePatch dll_patch_;
    // base swap of the exe launch; reverted right after CreateProcess but
    // kept around so the staged file name can be mapped back (see
    // normalize_swap_path)
    TransientPePatch exe_patch_;

    DEBUG_EVENT pending_{};
    bool has_pending_ = false;
    DWORD pending_status_ = DBG_CONTINUE;

    // full path handed to CreateProcessW for the process we are launching:
    // CREATE_PROCESS_DEBUG_INFO.hFile comes back NULL every now and then
    // (observed on Win11), and without a fallback the main module would be
    // registered with no path - and no symbols - for the whole session
    std::wstring launch_exe_path_;

    StopInfo stop_;
    uint32_t exit_code_ = 0;

    bool stop_at_entry_ = false;
    // set while we are still on the way to the entry point: the loader's own
    // breakpoint must not interrupt that
    bool awaiting_entry_ = false;

    int at_bp_id_ = 0;          // software breakpoint we are parked on
    int replant_pending_ = 0;   // re-arm this INT3 at the next stop
    int temp_bp_id_ = 0;        // one-shot breakpoint for step-over/until

    std::function<void(const std::string&)> command_hook_;  // on-hit commands
    std::vector<std::string> module_breaks_;               // module-load patterns
    bool in_hit_command_ = false;  // inside an on-hit command callback

    // temporary guard re-arm after a memory breakpoint hit
    int guard_rearm_id_ = 0;
    // execution hardware breakpoint slot disabled for an internal single step
    int hw_silent_slot_ = -1;
    // slot of the execution hardware breakpoint the session is parked on
    int at_hw_slot_ = -1;

    // set when a breakpoint condition was false: the next single step is an
    // internal bookkeeping step and must not stop the session
    bool silent_step_ = false;

    bool symbols_ready_ = false;

    // pid of the process Engine::pause injected DebugBreakProcess into: its
    // breakpoint must surface even while child loader breaks are being skipped
    uint32_t expecting_break_pid_ = 0;

    // software breakpoint ids lifted by the current lift_int3()/replant pair
    std::vector<int> lifted_;
};

}  // namespace aj
