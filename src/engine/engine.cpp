#include "engine/engine.h"

#include <dbghelp.h>
#include <psapi.h>

#include <cstring>

#include "engine/disasm.h"
#include "engine/exports.h"
#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

namespace {

DWORD kContinue = DBG_CONTINUE;
DWORD kNotHandled = DBG_EXCEPTION_NOT_HANDLED;

std::string module_name_from_base(HANDLE proc, uint64_t base) {
    wchar_t buf[MAX_PATH * 2] = {0};
    if (GetModuleFileNameExW(proc, (HMODULE)(uintptr_t)base, buf, MAX_PATH * 2))
        return to_utf8(buf);
    return {};
}

// The debuggee's loader has not inserted the new module into its PEB list yet
// while the LOAD_DLL event is being processed, so resolve the path from the
// file handle instead - that is always available at this point.
std::string path_from_file_handle(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return {};
    wchar_t buf[MAX_PATH * 2] = {0};
    DWORD n = GetFinalPathNameByHandleW(h, buf, MAX_PATH * 2,
                                        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!n || n >= MAX_PATH * 2) return {};
    std::string p = to_utf8(buf);
    if (starts_with(p, "\\\\?\\")) p = p.substr(4);
    return p;
}

std::string base_name_of(const std::string& path) {
    size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// A 64-bit debugger sees WOW64 targets through a different context API, so the
// bitness has to be known before touching registers or decoding instructions.
bool detect_wow64(HANDLE proc) {
    USHORT procMachine = 0, nativeMachine = 0;
    if (IsWow64Process2(proc, &procMachine, &nativeMachine))
        return procMachine != IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL wow = FALSE;
    if (IsWow64Process(proc, &wow)) return wow != FALSE;
    return false;
}

uint64_t pe_image_size(HANDLE proc, uint64_t base) {
    uint8_t dos[0x40];
    std::string err;
    if (!read_memory(proc, base, dos, sizeof(dos), err)) return 0;
    uint32_t lfanew = *(uint32_t*)(dos + 0x3C);
    uint8_t nth[4 + 20 + 0x40];
    if (!read_memory(proc, base + lfanew, nth, sizeof(nth), err)) return 0;
    // optional header starts at +24, SizeOfImage at +0x38 within it
    uint32_t size = *(uint32_t*)(nth + 4 + 20 + 0x38);
    return size;
}

// ImageBase from the PE header: this is where the loader puts the image when
// ASLR is off, and what a static disassembler uses as its base.
//
// Note: this must be read from the FILE, not from the mapped image. The loader
// rewrites the ImageBase field in the in-memory optional header to the actual
// load address, so reading the mapped image only ever yields the runtime base.
uint64_t pe_image_base_file(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return 0;
    uint8_t dos[0x40];
    DWORD got = 0;
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    if (!ReadFile(h, dos, sizeof(dos), &got, nullptr) || got != sizeof(dos)) return 0;
    uint32_t lfanew = *(uint32_t*)(dos + 0x3C);
    if (lfanew > 0x1000) return 0;
    uint8_t opt[0x30];
    SetFilePointer(h, (LONG)(lfanew + 24), nullptr, FILE_BEGIN);
    if (!ReadFile(h, opt, sizeof(opt), &got, nullptr) || got != sizeof(opt)) return 0;
    uint16_t magic = *(uint16_t*)opt;
    if (magic == 0x20B)   // PE32+
        return *(uint64_t*)(opt + 0x18);
    if (magic == 0x10B)   // PE32
        return *(uint32_t*)(opt + 0x1C);
    return 0;
}

uint64_t pe_image_base_path(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    uint64_t v = pe_image_base_file(h);
    CloseHandle(h);
    return v;
}

}  // namespace

// --------------------------------------------------------- fixed-base launch
// These live in namespace aj (not the anonymous one): engine.h declares them.

// IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is what makes the loader relocate the
// image; no per-process mitigation policy overrides it. To pin the load address
// to the PE ImageBase the flag has to be cleared before the loader reads it,
// so the header is patched and restored around the CreateProcess call.
constexpr uint16_t kDynamicBase = 0x0040;
constexpr uint16_t kHighEntropyVa = 0x0020;

struct PePatch {
    bool active = false;
    std::wstring path;
    HANDLE file = INVALID_HANDLE_VALUE;  // kept open: once the image is mapped
                                         // the file cannot be reopened for writing
    uint64_t offset = 0;
    uint8_t original[2] = {0, 0};
};

// A patched copy of the target whose image loads at the PE ImageBase. See the
// declaration in engine.h for why the original is never touched.
bool patch_file_disable_aslr(const std::wstring& path, std::string& err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = fmt("cannot open '%s' for patching: %s", to_utf8(path).c_str(),
                  last_error_text().c_str());
        return false;
    }
    auto fail = [&](const char* what) {
        err = fmt("cannot patch target: %s", what);
        CloseHandle(h);
        return false;
    };

    uint8_t dos[0x40];
    DWORD got = 0;
    if (!ReadFile(h, dos, sizeof(dos), &got, nullptr) || got != sizeof(dos))
        return fail("truncated DOS header");
    uint32_t lfanew = *(uint32_t*)(dos + 0x3C);
    if (lfanew > 0x1000) return fail("bad e_lfanew");

    uint8_t opt[0x50];
    SetFilePointer(h, (LONG)(lfanew + 24), nullptr, FILE_BEGIN);
    if (!ReadFile(h, opt, sizeof(opt), &got, nullptr) || got != sizeof(opt))
        return fail("truncated optional header");
    uint16_t magic = *(uint16_t*)opt;
    if (magic != 0x10B && magic != 0x20B) return fail("not a PE image");

    // DllCharacteristics sits at +0x46 in both PE32 and PE32+ optional headers
    uint16_t dllch = *(uint16_t*)(opt + 0x46);
    uint16_t patched = (uint16_t)(dllch & ~(kDynamicBase | kHighEntropyVa));
    if (patched == dllch) {
        CloseHandle(h);
        return true;
    }
    uint8_t nb[2] = {(uint8_t)patched, (uint8_t)(patched >> 8)};
    SetFilePointer(h, (LONG)(lfanew + 24 + 0x46), nullptr, FILE_BEGIN);
    if (!WriteFile(h, nb, 2, &got, nullptr) || got != 2) {
        err = "cannot write the patched header";
        CloseHandle(h);
        return false;
    }
    FlushFileBuffers(h);
    CloseHandle(h);
    return true;
}

std::wstring dir_of(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? std::wstring() : path.substr(0, p);
}
std::wstring name_of(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
}

bool make_fixed_base_copy(const std::wstring& original, FixedBaseCopy& out, std::string& err) {
    out = FixedBaseCopy();
    out.original = original;

    std::wstring dir = dir_of(original);
    std::wstring base = name_of(original);
    std::wstring hidden = dir.empty() ? std::wstring(L".aidbg-fixbase")
                                      : (dir + L"\\.aidbg-fixbase");
    if (!CreateDirectoryW(hidden.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        // the target's directory may be read-only; fall back to %TEMP%
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        hidden = std::wstring(tmp) + L"aidbg-fixbase";
        if (!CreateDirectoryW(hidden.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            err = "cannot create a directory for the fixed-base copy";
            return false;
        }
    }

    std::wstring copy = hidden + L"\\" + base;
    if (!CopyFileW(original.c_str(), copy.c_str(), FALSE)) {
        err = fmt("cannot copy the target: %s", last_error_text().c_str());
        return false;
    }
    // bring the debug database along so symbols still resolve
    size_t dot = base.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        std::wstring pdb = dir + L"\\" + base.substr(0, dot) + L".pdb";
        CopyFileW(pdb.c_str(), (hidden + L"\\" + base.substr(0, dot) + L".pdb").c_str(), TRUE);
    }

    if (!patch_file_disable_aslr(copy, err)) {
        DeleteFileW(copy.c_str());
        return false;
    }
    out.created = true;
    out.path = copy;
    out.dir = hidden;
    return true;
}

void cleanup_fixed_base_copy(FixedBaseCopy& c) {
    if (!c.created) return;
    // the image handle can outlive TerminateProcess for a moment, so retry
    auto drop = [](const std::wstring& p) {
        for (int i = 0; i < 20; ++i) {
            if (DeleteFileW(p.c_str())) return true;
            if (GetLastError() == ERROR_FILE_NOT_FOUND) return true;
            Sleep(50);
        }
        return false;
    };
    drop(c.path);
    std::wstring base = name_of(c.path);
    size_t dot = base.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        std::wstring stem = base.substr(0, dot);
        drop(c.dir + L"\\" + stem + L".pdb");
        drop(c.dir + L"\\" + stem + L".ilk");
        drop(c.dir + L"\\" + stem + L".obj");
    }
    RemoveDirectoryW(c.dir.c_str());
    c.created = false;
}

std::string stop_reason_text(StopReason r) {
    switch (r) {
        case StopReason::None: return "none";
        case StopReason::Entry: return "entry";
        case StopReason::Breakpoint: return "breakpoint";
        case StopReason::Step: return "step";
        case StopReason::Exception: return "exception";
        case StopReason::GuardBreak: return "memory_breakpoint";
        case StopReason::Exit: return "exit";
        case StopReason::SystemBreak: return "system_break";
        case StopReason::Timeout: return "timeout";
        case StopReason::ModuleLoad: return "module_load";
    }
    return "?";
}

Json StopInfo::to_json() const {
    Json j = Json::obj();
    j.set_str("reason", stop_reason_text(reason));
    if (!text.empty()) j.set_str("text", text);
    if (code) j.set_str("code", fmt("0x%08X", code));
    if (code) j.set_str("name", ExceptionPolicy::name_of(code));
    if (reason == StopReason::Exception) j.set_bool("first_chance", first_chance);
    if (address) j.set_hex("address", address);
    if (bp_id) j.set_i("bp_id", bp_id);
    if (reason == StopReason::Exit) j.set_u("exit_code", exit_code);
    return j;
}

Engine::Engine() {
    policy.reset_defaults();
    disasm_init(false);
    disasm_init(true);
    hide.bind(this);
}

Engine::~Engine() {
    sym.shutdown();
    for (auto& p : processes_) {
        for (auto& t : p.threads)
            if (t.handle) CloseHandle(t.handle);
        if (p.handle) CloseHandle(p.handle);
    }
    processes_.clear();
    cleanup_fixed_base_copy(fixbase_copy_);
}

// ---------------------------------------------------------------- processes

ProcessInfo* Engine::proc_by_pid(uint32_t pid) {
    for (auto& p : processes_)
        if (p.pid == pid) return &p;
    return nullptr;
}

ProcessInfo* Engine::cur_proc() {
    return current_pid_ ? proc_by_pid(current_pid_) : nullptr;
}

const ProcessInfo* Engine::cur_proc() const {
    for (const auto& p : processes_)
        if (p.pid == current_pid_) return &p;
    return nullptr;
}

void Engine::sync_thread_handle() {
    thread_handle_ = nullptr;
    ProcessInfo* p = cur_proc();
    if (!p) return;
    for (auto& t : p->threads) {
        if (t.tid == current_tid_ && t.alive && t.handle) {
            thread_handle_ = t.handle;
            return;
        }
    }
    for (auto& t : p->threads) {
        if (t.alive && t.handle) {
            thread_handle_ = t.handle;
            current_tid_ = t.tid;
            return;
        }
    }
}

void Engine::pick_live_process() {
    for (auto& p : processes_) {
        if (p.alive) {
            current_pid_ = p.pid;
            sync_thread_handle();
            return;
        }
    }
    current_pid_ = 0;
    current_tid_ = 0;
    thread_handle_ = nullptr;
}

bool Engine::set_current_process(uint32_t pid, std::string& err) {
    ProcessInfo* p = proc_by_pid(pid);
    if (!p || !p->alive) {
        err = fmt("no such live process: %u", pid);
        return false;
    }
    current_pid_ = pid;
    sync_thread_handle();
    return true;
}

void Engine::set_tid(uint32_t tid) {
    current_tid_ = tid;
    sync_thread_handle();
}

HANDLE Engine::process() const {
    const ProcessInfo* p = cur_proc();
    return p ? p->handle : nullptr;
}

bool Engine::is32() const {
    const ProcessInfo* p = cur_proc();
    return p && p->is32;
}

size_t Engine::pointer_size() const { return is32() ? 4 : 8; }

const char* Engine::arch_text() const { return is32() ? "x86" : "x64"; }

std::vector<ModuleInfo>& Engine::modules() {
    static std::vector<ModuleInfo> empty;
    ProcessInfo* p = cur_proc();
    return p ? p->modules : empty;
}

std::vector<ThreadInfo>& Engine::threads() {
    static std::vector<ThreadInfo> empty;
    ProcessInfo* p = cur_proc();
    return p ? p->threads : empty;
}

// ---------------------------------------------------------------- session

bool Engine::launch(const std::string& exe, const std::string& args, const std::string& cwd,
                    bool new_console, bool follow_children, bool fixed_base, std::string& err) {
    if (!processes_.empty()) {
        err = "a target is already active; detach or kill it first";
        return false;
    }
    std::wstring wexe = to_wide(exe);
    std::wstring cmdline = L"\"" + wexe + L"\"";
    if (!args.empty()) cmdline += L" " + to_wide(args);

    // The debuggee's stdout must never interleave with our JSON stream, so by
    // default it gets no console at all. Use --console when its output matters.
    // DEBUG_PROCESS also reports processes the target spawns; DEBUG_ONLY_THIS_PROCESS
    // keeps the session to a single process.
    DWORD flags = (follow_children ? DEBUG_PROCESS : DEBUG_ONLY_THIS_PROCESS) |
                  (new_console ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
    follow_children_ = follow_children;

    // Turning ASLR off makes the loader honour the PE ImageBase, so the runtime
    // addresses line up with what a static disassembler shows (0x140000000 for
    // x64, 0x400000 for x86 by default). The original file is never modified:
    // a patched copy is launched instead (see make_fixed_base_copy).
    std::wstring launch_path = wexe;
    std::wstring launch_cmd = cmdline;
    fixbase_copy_ = FixedBaseCopy();
    if (fixed_base) {
        std::string copy_err;
        if (!make_fixed_base_copy(wexe, fixbase_copy_, copy_err)) {
            err = copy_err;
            return false;
        }
        if (fixbase_copy_.created) {
            launch_path = fixbase_copy_.path;
            launch_cmd = L"\"" + launch_path + L"\"";
            if (!args.empty()) launch_cmd += L" " + to_wide(args);
        }
    }

    STARTUPINFOW si;
    std::memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    std::memset(&pi, 0, sizeof(pi));
    std::wstring wcwd = cwd.empty() ? std::wstring() : to_wide(cwd);
    BOOL ok = CreateProcessW(launch_path.c_str(), launch_cmd.data(), nullptr, nullptr, FALSE,
                             flags, nullptr, wcwd.empty() ? nullptr : wcwd.c_str(), &si, &pi);
    DWORD create_err = ok ? 0 : GetLastError();
    if (!ok) {
        cleanup_fixed_base_copy(fixbase_copy_);
        err = fmt("CreateProcess(%s) failed: %s", exe.c_str(), last_error_text(create_err).c_str());
        return false;
    }
    // The CREATE_PROCESS event hands us the handles to keep; drop these.
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    stop_at_entry_ = true;
    awaiting_entry_ = true;
    stop_ = StopInfo{};
    // pump the debug loop until the first meaningful stop (the entry breakpoint)
    return wait_for_stop(0, err);
}

bool Engine::attach(uint32_t pid, std::string& err) {
    if (!processes_.empty()) {
        err = "a target is already active; detach or kill it first";
        return false;
    }
    if (!DebugActiveProcess(pid)) {
        err = fmt("DebugActiveProcess(%u) failed: %s", pid, last_error_text().c_str());
        return false;
    }
    DebugSetProcessKillOnExit(FALSE);
    follow_children_ = true;
    stop_at_entry_ = false;
    stop_ = StopInfo{};
    // pump until the loader's initial breakpoint pauses the session
    return wait_for_stop(0, err);
}

// Closes every process/thread handle held for the debuggees.
static void release_all(std::vector<ProcessInfo>& processes) {
    for (auto& p : processes) {
        for (auto& t : p.threads)
            if (t.handle) CloseHandle(t.handle);
        if (p.handle) CloseHandle(p.handle);
    }
    processes.clear();
}

bool Engine::detach(std::string& err) {
    if (processes_.empty()) {
        err = "no active target";
        return false;
    }
    // restore any planted breakpoints so the targets keep working
    hide.unplant_all();  // ntdll hook INT3s must not survive the detach
    for (auto& bp : bps.all()) {
        if (bp.kind == BpKind::Software) {
            for (auto& kv : bp.plants) {
                ProcessInfo* p = proc_by_pid(kv.first);
                if (p && kv.second.planted) bps.unplant_software(p->handle, kv.first, bp, err);
            }
        } else if (bp.kind == BpKind::Memory) {
            for (auto& kv : bp.plants) {
                if (!kv.second.planted) continue;
                DWORD old = 0;
                protect_memory(proc_by_pid(kv.first)->handle, kv.second.region_base,
                               kv.second.region_size, kv.second.region_protect, old, err);
                kv.second.planted = false;
            }
        }
    }

    continue_pending(pending_status_);
    for (auto& p : processes_)
        if (p.alive) DebugActiveProcessStop(p.pid);
    sym.shutdown();
    release_all(processes_);
    current_pid_ = 0;
    current_tid_ = 0;
    thread_handle_ = nullptr;
    has_pending_ = false;
    stop_ = StopInfo{};
    cleanup_fixed_base_copy(fixbase_copy_);
    return true;
}

bool Engine::kill(std::string& err) {
    if (processes_.empty()) {
        err = "no active target";
        return false;
    }
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Software) continue;
        for (auto& kv : bp.plants) {
            ProcessInfo* p = proc_by_pid(kv.first);
            if (p && kv.second.planted) bps.unplant_software(p->handle, kv.first, bp, err);
        }
    }
    continue_pending(pending_status_);
    for (auto& p : processes_)
        if (p.alive) TerminateProcess(p.handle, 1);
    // drain remaining events so the debug session ends cleanly
    DEBUG_EVENT ev;
    for (int i = 0; i < 256; ++i) {
        if (!WaitForDebugEvent(&ev, 200)) break;
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
    sym.shutdown();
    release_all(processes_);
    current_pid_ = 0;
    current_tid_ = 0;
    thread_handle_ = nullptr;
    has_pending_ = false;
    stop_ = StopInfo{StopReason::Exit, "process terminated"};
    cleanup_fixed_base_copy(fixbase_copy_);
    return true;
}

SessionMeta Engine::session_meta() const {
    SessionMeta m;
    m.active = !processes_.empty();
    m.pid = current_pid_;
    m.tid = current_tid_;
    if (!m.active) {
        m.state = "idle";
        return m;
    }
    m.state = has_pending_ ? "paused" : "running";
    m.stop_reason = stop_reason_text(stop_.reason);
    m.detail = stop_.text;
    m.arch = arch_text();
    m.process_count = processes_.size();
    if (has_pending_ && thread_handle_) {
        CpuState st;
        std::string e;
        if (aj::get_state(thread_handle_, is32(), st, e)) m.rip = hex8(st.rip);
    }
    return m;
}

bool Engine::get_state(CpuState& out, std::string& err) {
    if (!thread_handle_) {
        err = "no current thread";
        return false;
    }
    return aj::get_state(thread_handle_, is32(), out, err);
}

bool Engine::set_state(const CpuState& st, std::string& err) {
    if (!thread_handle_) {
        err = "no current thread";
        return false;
    }
    return aj::set_state(thread_handle_, st, err);
}

const ModuleInfo* Engine::module_at(uint64_t addr) const {
    for (const auto& p : processes_)
        for (const auto& m : p.modules)
            if (addr >= m.base && addr < m.base + m.size) return &m;
    return nullptr;
}

const ModuleInfo* Engine::module_by_name(const std::string& name) const {
    std::string want = to_lower(name);
    auto matches = [&](const ModuleInfo& m) {
        if (to_lower(m.name) == want) return true;
        std::string stem = m.name;
        size_t dot = stem.find_last_of('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        return to_lower(stem) == want;
    };
    if (const ProcessInfo* cp = cur_proc())
        for (const auto& m : cp->modules)
            if (matches(m)) return &m;
    for (const auto& p : processes_)
        for (const auto& m : p.modules)
            if (matches(m)) return &m;
    return nullptr;
}

// ---------------------------------------------------------------- events

void Engine::continue_pending(DWORD status) {
    if (has_pending_) {
        ContinueDebugEvent(pending_.dwProcessId, pending_.dwThreadId, status);
        has_pending_ = false;
    }
}

bool Engine::wait_for_stop(uint32_t timeout_ms, std::string& err) {
    while (true) {
        if (!has_pending_) {
            DWORD t = timeout_ms ? timeout_ms : INFINITE;
            if (!WaitForDebugEvent(&pending_, t)) {
                DWORD e = GetLastError();
                if (timeout_ms && (e == ERROR_SEM_TIMEOUT || e == 121)) {
                    stop_ = StopInfo{StopReason::Timeout, "timed out waiting for a debug event"};
                    err = fmt("timeout after %u ms", timeout_ms);
                    return false;
                }
                err = fmt("WaitForDebugEvent failed: %s", last_error_text(e).c_str());
                return false;
            }
            has_pending_ = true;
            pending_status_ = kContinue;
        }
        DEBUG_EVENT ev = pending_;
        bool stop = false;
        DWORD status = kContinue;
        process_event(ev, stop, status);
        pending_status_ = status;
        if (stop) return true;  // left pending: the debuggee is frozen here
        continue_pending(status);
    }
}

bool Engine::resume_wait(uint32_t timeout_ms, std::string& err) {
    // The pause state is "event received but not yet continued". Resuming means
    // continuing that event first, then waiting for the next one. Processing it
    // twice would re-report the very breakpoint we just left.
    continue_pending(pending_status_);
    return wait_for_stop(timeout_ms, err);
}

void Engine::process_event(DEBUG_EVENT& ev, bool& stop, DWORD& status) {
    stop = false;
    status = kContinue;
    // every event belongs to one process/thread pair: adopt it as current so
    // follow-up commands inspect exactly what just stopped
    current_pid_ = ev.dwProcessId;
    current_tid_ = ev.dwThreadId;
    sync_thread_handle();

    switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: on_create_process(ev); break;
        case EXIT_PROCESS_DEBUG_EVENT: {
            on_exit_process(ev);
            bool any_alive = false;
            for (auto& p : processes_)
                if (p.alive) any_alive = true;
            stop = !any_alive;  // a child exiting does not end the session
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: on_create_thread(ev); break;
        case EXIT_THREAD_DEBUG_EVENT: on_exit_thread(ev); break;
        case LOAD_DLL_DEBUG_EVENT: on_load_dll(ev, stop); break;
        case UNLOAD_DLL_DEBUG_EVENT: on_unload_dll(ev); break;
        case OUTPUT_DEBUG_STRING_EVENT: {
            OUTPUT_DEBUG_STRING_INFO& i = ev.u.DebugString;
            ProcessInfo* p = proc_by_pid(ev.dwProcessId);
            if (p && i.lpDebugStringData && i.nDebugStringLength) {
                std::string buf(i.nDebugStringLength, '\0');
                std::string e;
                if (read_memory(p->handle, (uint64_t)i.lpDebugStringData, buf.data(),
                                i.nDebugStringLength, e)) {
                    buf.resize(std::strlen(buf.c_str()));
                    Json d = Json::obj();
                    d.set_u("pid", ev.dwProcessId);
                    Output::instance().event("debug_string", trim(buf), d);
                }
            }
            break;
        }
        case RIP_EVENT: break;
        case EXCEPTION_DEBUG_EVENT: on_exception(ev, stop, status); break;
        default: break;
    }
}

void Engine::on_create_process(DEBUG_EVENT& ev) {
    CREATE_PROCESS_DEBUG_INFO& i = ev.u.CreateProcessInfo;

    ProcessInfo p;
    p.pid = ev.dwProcessId;
    p.handle = i.hProcess;
    p.is32 = detect_wow64(i.hProcess);
    p.entry = (uint64_t)i.lpStartAddress;
    p.alive = true;
    // a process appearing after the first one is a child of the debuggee
    p.is_child = !processes_.empty();

    ModuleInfo m;
    m.base = (uint64_t)i.lpBaseOfImage;
    m.entry = p.entry;
    m.size = pe_image_size(p.handle, m.base);
    m.preferred_base = pe_image_base_file(i.hFile);
    m.path = path_from_file_handle(i.hFile);
    if (m.path.empty()) m.path = module_name_from_base(p.handle, m.base);
    if (!m.preferred_base) m.preferred_base = pe_image_base_path(to_wide(m.path));
    m.name = base_name_of(m.path);
    p.modules.push_back(m);
    p.exe_name = m.name;
    p.exe_path = m.path;

    if (i.hFile) CloseHandle(i.hFile);

    ThreadInfo t;
    t.tid = ev.dwThreadId;
    t.handle = i.hThread;
    t.entry = (uint64_t)i.lpStartAddress;
    p.threads.push_back(t);

    processes_.push_back(std::move(p));
    ProcessInfo& np = processes_.back();
    current_pid_ = np.pid;
    current_tid_ = ev.dwThreadId;
    sync_thread_handle();

    if (!symbols_ready_) {
        std::string e;
        symbols_ready_ = sym.init(np.handle, "", e);
    }
    std::string e;
    sym.load_module(m.base, (size_t)m.size, m.path, m.name, e);

    // breakpoints the session already knows about must appear in this process too
    resolve_deferred_breakpoints();

    // anti-anti-debug: PEB patches first (before the target can observe them),
    // hook INT3s once ntdll shows up
    hide.on_process(np.pid, np.handle, np.is32);

    // only the process the user launched gets the entry-point stop
    if (stop_at_entry_ && np.entry) {
        Breakpoint bp;
        bp.kind = BpKind::Software;
        bp.address = np.entry;
        bp.temporary = true;
        bp.symbol = "$entry";
        bp.temp_purpose = "entry";
        int id = bps.add(bp);
        Breakpoint* bp2 = bps.find(id);
        if (bp2) {
            if (!bps.plant_software(np.handle, np.pid, *bp2, e)) {
                // entry may be on a non-writable page; fall back to the system breakpoint
                bps.remove(id);
                awaiting_entry_ = false;
            }
        } else {
            awaiting_entry_ = false;
        }
        stop_at_entry_ = false;
    }
}

void Engine::on_exit_process(DEBUG_EVENT& ev) {
    exit_code_ = ev.u.ExitProcess.dwExitCode;
    uint32_t pid = ev.dwProcessId;
    ProcessInfo* p = proc_by_pid(pid);
    if (p) p->alive = false;
    hide.on_process_exit(pid);

    bool any_alive = false;
    for (auto& q : processes_)
        if (q.alive) any_alive = true;

    if (any_alive) {
        Json d = Json::obj();
        d.set_u("pid", pid);
        d.set_u("exit_code", exit_code_);
        Output::instance().event("process_exit",
                                 fmt("process %u exited with code %u", pid, exit_code_), d);
        pick_live_process();
    } else {
        stop_ = StopInfo{StopReason::Exit, fmt("process exited with code %u", exit_code_)};
        stop_.exit_code = exit_code_;
        sym.shutdown();
    }
}

void Engine::on_load_dll(DEBUG_EVENT& ev, bool& stop) {
    ProcessInfo* p = proc_by_pid(ev.dwProcessId);
    if (!p) return;
    LOAD_DLL_DEBUG_INFO& i = ev.u.LoadDll;
    uint64_t base = (uint64_t)i.lpBaseOfDll;
    ModuleInfo m;
    m.base = base;
    m.entry = base;
    m.size = pe_image_size(p->handle, base);
    m.preferred_base = pe_image_base_file(i.hFile);
    m.path = path_from_file_handle(i.hFile);
    if (m.path.empty()) m.path = module_name_from_base(p->handle, base);
    if (!m.preferred_base) m.preferred_base = pe_image_base_path(to_wide(m.path));
    m.name = base_name_of(m.path);
    if (m.path.empty()) m.path = module_name_from_base(p->handle, base);
    m.name = base_name_of(m.path);
    p->modules.push_back(m);
    if (i.hFile) CloseHandle(i.hFile);

    std::string e;
    sym.load_module(m.base, (size_t)m.size, m.path, m.name, e);
    resolve_deferred_breakpoints();
    hide.on_module_loaded(p->pid, p->handle, p->is32, m.name);

    // module-load breakpoints: stop when a watched module shows up
    for (const auto& pat : module_breaks_) {
        if (!wild_match(m.name, pat) && !wild_match(m.path, pat)) continue;
        stop_ = StopInfo{StopReason::ModuleLoad,
                         fmt("module loaded: %s at %s", m.name.c_str(), hex8(m.base).c_str())};
        stop_.address = m.base;
        stop = true;
        break;
    }
}

void Engine::on_unload_dll(DEBUG_EVENT& ev) {
    uint64_t base = (uint64_t)ev.u.UnloadDll.lpBaseOfDll;
    sym.unload_module(base);
    ProcessInfo* p = proc_by_pid(ev.dwProcessId);
    if (!p) return;
    for (size_t i = 0; i < p->modules.size(); ++i) {
        if (p->modules[i].base == base) {
            p->modules.erase(p->modules.begin() + (long)i);
            break;
        }
    }
}

void Engine::on_create_thread(DEBUG_EVENT& ev) {
    ProcessInfo* p = proc_by_pid(ev.dwProcessId);
    if (!p) return;
    CREATE_THREAD_DEBUG_INFO& i = ev.u.CreateThread;
    ThreadInfo t;
    t.tid = ev.dwThreadId;
    t.handle = i.hThread;
    t.entry = (uint64_t)i.lpStartAddress;
    p->threads.push_back(t);
    sync_thread_handle();
    std::string e;
    plant_all_hardware(e);
}

void Engine::on_exit_thread(DEBUG_EVENT& ev) {
    ProcessInfo* p = proc_by_pid(ev.dwProcessId);
    if (!p) return;
    for (auto& t : p->threads) {
        if (t.tid == ev.dwThreadId) {
            t.alive = false;
            if (t.handle && t.handle != thread_handle_) {
                CloseHandle(t.handle);
                t.handle = nullptr;
            }
            break;
        }
    }
}

void Engine::refresh_threads() {
    for (auto& p : processes_) {
        for (size_t i = 0; i < p.threads.size();) {
            if (!p.threads[i].alive) {
                p.threads.erase(p.threads.begin() + (long)i);
            } else {
                ++i;
            }
        }
    }
}

// ---------------------------------------------------------------- exceptions

void Engine::on_exception(DEBUG_EVENT& ev, bool& stop, DWORD& status) {
    EXCEPTION_RECORD& er = ev.u.Exception.ExceptionRecord;
    uint32_t code = (uint32_t)er.ExceptionCode;
    uint64_t addr = (uint64_t)er.ExceptionAddress;
    bool first_chance = ev.u.Exception.dwFirstChance != 0;
    policy.note_hit(code);

    // WOW64 reports the x86 equivalents with their own codes; treat them exactly
    // like the native breakpoint / single-step exceptions.
    uint32_t norm = code;
    if (norm == 0x4000001F)
        norm = EXCEPTION_BREAKPOINT;
    else if (norm == 0x4000001E)
        norm = EXCEPTION_SINGLE_STEP;

    // ---- single step ----
    if (norm == EXCEPTION_SINGLE_STEP) {
        // a pass-through hook (NtClose and friends) replants its INT3 here and
        // the step itself must stay invisible to the user
        if (hide.on_single_step()) {
            stop = false;
            status = kContinue;
            return;
        }
        CpuState st;
        std::string e;
        if (get_state(st, e)) {
            if (st.dr6 & 0x0F) {
                st.dr6 = 0;
                set_state(st, e);
                handle_hardware_breakpoint(ev.dwThreadId, stop);
                if (stop) {
                    status = kContinue;
                    return;
                }
            }
        }
        if (replant_pending_) replant_if_pending();
        if (guard_rearm_id_) {
            Breakpoint* gb = bps.find(guard_rearm_id_);
            if (gb) arm_guard(*gb, current_pid_, e);
            guard_rearm_id_ = 0;
        }
        if (silent_step_) {
            silent_step_ = false;
            stop = false;
            status = kContinue;
            return;
        }
        stop_ = StopInfo{StopReason::Step, "single step completed"};
        stop_.address = addr;
        stop = true;
        status = kContinue;
        return;
    }

    // ---- software breakpoint (INT3) ----
    if (norm == EXCEPTION_BREAKPOINT) {
        // anti-anti-debug hook sites answer the call themselves and the target
        // keeps running; they must never surface as a breakpoint hit
        if (hide.on_breakpoint(addr, stop)) {
            status = kContinue;
            return;
        }
        Breakpoint* bp = bps.at_address(addr);
        if (bp && bp->plant_of(current_pid_).planted) {
            if (handle_software_breakpoint(addr, bp, stop)) {
                status = kContinue;
                return;
            }
            status = kContinue;
            return;
        }
        // A process spawned by the debuggee raises its own loader breakpoints on
        // the way in (ntdll's, and WOW64 adds another). Those are startup
        // mechanics, not places the user asked to stop, so walk past them. The
        // check is deliberately narrow: only ntdll / the WOW64 layer qualifies,
        // so a breakpoint inside the target or its DLLs is never swallowed.
        ProcessInfo* cp = proc_by_pid(ev.dwProcessId);
        if (cp && cp->is_child && cp->startup_breaks_skipped < 3) {
            const ModuleInfo* fm = nullptr;
            for (const auto& mm : cp->modules)
                if (addr >= mm.base && addr < mm.base + mm.size) {
                    fm = &mm;
                    break;
                }
            std::string mn = fm ? to_lower(fm->name) : std::string();
            if (mn == "ntdll.dll" || starts_with(mn, "wow64")) {
                cp->startup_breaks_skipped++;
                stop = false;
                status = kContinue;
                return;
            }
        }
        // system / foreign breakpoint: report and pause
        if (awaiting_entry_) {
            // still travelling to the entry point: WOW64 and the loader raise
            // their own breakpoints on the way and those are not where the user
            // asked to stop
            stop = false;
            status = kContinue;
            return;
        }
        stop_ = StopInfo{StopReason::SystemBreak, "breakpoint exception (not owned by aidbg)"};
        stop_.code = code;
        stop_.address = addr;
        stop_.first_chance = first_chance;
        stop = true;
        status = kContinue;
        return;
    }

    // ---- guard page (memory breakpoint) ----
    if (code == STATUS_GUARD_PAGE_VIOLATION) {
        uint64_t access_addr = (uint64_t)er.ExceptionInformation[1];
        if (handle_guard_breakpoint(access_addr, stop)) {
            status = kContinue;
            return;
        }
        // not one of ours: let the debuggee deal with it
        stop = false;
        status = kNotHandled;
        return;
    }

    // ---- everything else follows the exception policy ----
    ExAction act = policy.lookup(code);
    if (first_chance && act == ExAction::Ignore) {
        stop = false;
        status = kNotHandled;
        return;
    }
    if (first_chance && act == ExAction::Pass) {
        stop = false;
        status = kContinue;
        return;
    }
    stop_ = StopInfo{StopReason::Exception,
                     fmt("%s exception at %s", ExceptionPolicy::name_of(code).c_str(),
                         hex8(addr).c_str())};
    stop_.code = code;
    stop_.address = addr;
    stop_.first_chance = first_chance;
    stop = true;
    status = kNotHandled;
}

bool Engine::handle_software_breakpoint(uint64_t addr, Breakpoint* bp, bool& stop) {
    std::string e;
    // capture fields first: removing a breakpoint invalidates `bp`
    const int bp_id = bp->id;
    const std::string bp_symbol = bp->symbol;
    const bool bp_temp = bp->temporary;
    const std::string bp_condition = bp->condition;
    const std::string bp_command = bp->command;
    awaiting_entry_ = false;  // any of our own breakpoints ends the entry search
    const std::string bp_purpose = bp->temp_purpose;

    // restore original instruction byte and rewind the instruction pointer onto it
    bps.unplant_software(process(), current_pid_, *bp, e);
    CpuState st;
    if (get_state(st, e)) {
        st.rip = addr;
        set_state(st, e);
    }
    bp->hit_count++;
    at_bp_id_ = bp_id;
    if (!bp_command.empty() && command_hook_) command_hook_(bp_command);

    bool should_stop = true;
    if (!bp_condition.empty()) {
        Breakpoint tmp;
        tmp.condition = bp_condition;
        if (!evaluate_condition(tmp, should_stop, e)) should_stop = true;
    }
    if (!should_stop) {
        // silent auto-continue: step over the instruction then re-plant
        replant_pending_ = bp_id;
        at_bp_id_ = 0;
        silent_step_ = true;
        set_trap_flag(true, e);
        stop = false;
        return true;
    }

    if (bp_temp) {
        // one-shot: drop it after it fired
        replant_pending_ = 0;
        bps.remove(bp_id);
        at_bp_id_ = 0;
    }

    if (bp_purpose == "entry") {
        awaiting_entry_ = false;
        stop_ = StopInfo{StopReason::Entry, fmt("entry point reached at %s", hex8(addr).c_str())};
        stop_.address = addr;
        stop = true;
        return true;
    }
    if (!bp_purpose.empty()) {
        std::string text = "step over completed";
        if (bp_purpose == "step_out")
            text = "step out completed";
        else if (bp_purpose == "run_until")
            text = "reached requested address";
        stop_ = StopInfo{StopReason::Step, text + " at " + hex8(addr)};
        stop_.address = addr;
        stop = true;
        return true;
    }

    stop_ = StopInfo{StopReason::Breakpoint, fmt("breakpoint %d hit", bp_id)};
    stop_.address = addr;
    stop_.bp_id = bp_id;
    if (!bp_symbol.empty()) stop_.text += " (" + bp_symbol + ")";
    if (bp_temp) stop_.text += " [temporary]";
    stop = true;
    return true;
}

bool Engine::handle_hardware_breakpoint(uint32_t /*tid*/, bool& stop) {
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Hardware || !bp.enabled) continue;
        bool should_stop = true;
        std::string e;
        if (!bp.command.empty() && command_hook_) command_hook_(bp.command);
        evaluate_condition(bp, should_stop, e);
        bp.hit_count++;
        if (!should_stop) continue;
        stop_ = StopInfo{StopReason::Breakpoint, fmt("hardware breakpoint %d hit", bp.id)};
        stop_.address = bp.address;
        stop_.bp_id = bp.id;
        stop = true;
        return true;
    }
    stop = true;
    stop_ = StopInfo{StopReason::Step, "hardware step completed"};
    return true;
}

bool Engine::handle_guard_breakpoint(uint64_t access_addr, bool& stop) {
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Memory || !bp.enabled) continue;
        if (access_addr < bp.address || access_addr >= bp.address + bp.size) continue;
        std::string e;
        bool should_stop = true;
        if (!bp.command.empty() && command_hook_) command_hook_(bp.command);
        evaluate_condition(bp, should_stop, e);
        bp.hit_count++;
        guard_rearm_id_ = bp.id;  // re-arm after stepping past
        if (!should_stop) {
            silent_step_ = true;
            set_trap_flag(true, e);
            stop = false;
            return true;
        }
        stop_ = StopInfo{StopReason::GuardBreak,
                         fmt("memory breakpoint %d hit at %s", bp.id, hex8(access_addr).c_str())};
        stop_.address = access_addr;
        stop_.bp_id = bp.id;
        stop = true;
        return true;
    }
    return false;
}

bool Engine::evaluate_condition(Breakpoint& bp, bool& should_stop, std::string& err) {
    should_stop = true;
    if (bp.condition.empty()) return true;
    uint64_t v = 0;
    if (!eval(bp.condition, v, err)) return false;
    should_stop = (v != 0);
    return true;
}

// ---------------------------------------------------------------- stepping

bool Engine::set_trap_flag(bool enable, std::string& err) {
    CpuState st;
    if (!get_state(st, err)) return false;
    if (enable)
        st.rflags |= 0x100;
    else
        st.rflags &= ~0x100u;
    return set_state(st, err);
}

void Engine::replant_if_pending() {
    if (!replant_pending_) return;
    Breakpoint* bp = bps.find(replant_pending_);
    std::string e;
    if (bp && bp->enabled) bps.plant_software(process(), current_pid_, *bp, e);
    replant_pending_ = 0;
}

bool Engine::single_step(std::string& err) {
    if (!set_trap_flag(true, err)) return false;
    continue_pending(pending_status_);
    return wait_for_stop(0, err);
}

bool Engine::single_step_replant(std::string& err) {
    replant_pending_ = at_bp_id_;
    at_bp_id_ = 0;
    if (!set_trap_flag(true, err)) return false;
    continue_pending(pending_status_);
    return wait_for_stop(0, err);
}

bool Engine::resume(ResumeAction act, uint64_t until_addr, uint32_t timeout_ms,
                    std::string& err) {
    bool ok = resume_inner(act, until_addr, timeout_ms, err);
    if (ok) maybe_auto_snapshot();
    return ok;
}

void Engine::maybe_auto_snapshot() {
    if (!snaps.auto_enabled() || !is_paused()) return;
    if (stop_.reason == StopReason::Exit || stop_.reason == StopReason::None) return;
    std::string e;
    CpuState st;
    if (!get_state(st, e)) return;
    snaps.capture(process(), is32(), current_pid_, st, stop_.text, "", e);
}

bool Engine::snapshot_save(const std::string& name, std::string& err) {
    if (!is_paused()) {
        err = "target is not paused";
        return false;
    }
    CpuState st;
    if (!get_state(st, err)) return false;
    return snaps.capture(process(), is32(), current_pid_, st, stop_.text, name, err);
}

bool Engine::snapshot_restore(const std::string& name, std::string& err) {
    if (!is_paused()) {
        err = "target is not paused";
        return false;
    }
    // Take every planted INT3 out first: the snapshot holds real instruction
    // bytes and restoring on top of our patches would corrupt the code.
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Software) continue;
        for (auto& kv : bp.plants)
            if (kv.second.planted) bps.unplant_software(process(), kv.first, bp, err);
    }

    if (!snaps.restore_by_name(process(), thread_handle_, name, err)) return false;

    // put the breakpoints back
    std::string e;
    for (auto& bp : bps.all()) {
        if (!bp.enabled) continue;
        if (bp.kind == BpKind::Software)
            bps.plant_software(process(), current_pid_, bp, e);
        else if (bp.kind == BpKind::Hardware)
            plant_all_hardware(e);
    }

    // the restored RIP may sit exactly on a breakpoint: park on it like a hit
    at_bp_id_ = 0;
    replant_pending_ = 0;
    guard_rearm_id_ = 0;
    silent_step_ = false;
    CpuState st;
    if (get_state(st, e)) {
        Breakpoint* bp = bps.at_address(st.rip);
        if (bp) {
            bps.unplant_software(process(), current_pid_, *bp, e);
            at_bp_id_ = bp->id;
        }
    }
    stop_ = StopInfo{StopReason::Step, "restored from snapshot"};
    return true;
}

bool Engine::resume_inner(ResumeAction act, uint64_t until_addr, uint32_t timeout_ms,
                          std::string& err) {
    if (!active()) {
        // the handle lingers after EXIT_PROCESS, so check liveness explicitly:
        // stepping a dead debuggee would wait forever for an event that never
        // arrives
        err = "the target has exited";
        return false;
    }
    if (!has_pending_) {
        err = "target is not paused";
        return false;
    }

    bool at_sw_bp = at_bp_id_ != 0;
    bool at_guard = guard_rearm_id_ != 0;

    switch (act) {
        case ResumeAction::StepInto: {
            if (at_sw_bp || at_guard) return single_step_replant(err);
            return single_step(err);
        }
        case ResumeAction::Continue: {
            if (at_sw_bp || at_guard) {
                if (!single_step_replant(err)) return false;
                if (stop_.reason == StopReason::Exception) return false;
            }
            return resume_wait(timeout_ms, err);
        }
        case ResumeAction::StepOver: {
            CpuState st;
            if (!get_state(st, err)) return false;
            uint64_t rip = st.rip;
            uint8_t code[32] = {0};
            std::string e;
            read_memory(process(), rip, code, sizeof(code), e);
            Insn insn;
            bool decoded = decode_one(code, sizeof(code), rip, insn, is32());
            if (decoded && (insn.is_call || insn.is_loop) && !insn.is_rep) {
                // run to the instruction after the call
                Breakpoint bp;
                bp.kind = BpKind::Software;
                bp.address = rip + insn.length;
                bp.temporary = true;
                bp.temp_purpose = "step_over";
                int id = bps.add(bp);
                Breakpoint* p = bps.find(id);
                if (p && !bps.plant_software(process(), current_pid_, *p, err)) {
                    bps.remove(id);
                    return false;
                }
                temp_bp_id_ = id;
                if (at_sw_bp || at_guard) {
                    replant_pending_ = at_bp_id_;
                    at_bp_id_ = 0;
                    if (guard_rearm_id_) {
                        Breakpoint* gb = bps.find(guard_rearm_id_);
                        if (gb) arm_guard(*gb, current_pid_, e);
                        guard_rearm_id_ = 0;
                    }
                }
                return resume_wait(timeout_ms, err);
            }
            if (at_sw_bp || at_guard) return single_step_replant(err);
            return single_step(err);
        }
        case ResumeAction::StepOut: {
            uint64_t ret = 0;
            if (!return_address(ret, err)) return false;
            Breakpoint bp;
            bp.kind = BpKind::Software;
            bp.address = ret;
            bp.temporary = true;
            bp.temp_purpose = "step_out";
            int id = bps.add(bp);
            Breakpoint* p = bps.find(id);
            if (p && !bps.plant_software(process(), current_pid_, *p, err)) {
                bps.remove(id);
                return false;
            }
            temp_bp_id_ = id;
            if (at_sw_bp || at_guard) {
                replant_pending_ = at_bp_id_;
                at_bp_id_ = 0;
                if (guard_rearm_id_) {
                    std::string e;
                    Breakpoint* gb = bps.find(guard_rearm_id_);
                    if (gb) arm_guard(*gb, current_pid_, e);
                    guard_rearm_id_ = 0;
                }
            }
            return resume_wait(timeout_ms, err);
        }
        case ResumeAction::RunUntil: {
            Breakpoint bp;
            bp.kind = BpKind::Software;
            bp.address = until_addr;
            bp.temporary = true;
            bp.temp_purpose = "run_until";
            int id = bps.add(bp);
            Breakpoint* p = bps.find(id);
            if (p && !bps.plant_software(process(), current_pid_, *p, err)) {
                bps.remove(id);
                return false;
            }
            temp_bp_id_ = id;
            if (at_sw_bp || at_guard) {
                replant_pending_ = at_bp_id_;
                at_bp_id_ = 0;
                if (guard_rearm_id_) {
                    std::string e;
                    Breakpoint* gb = bps.find(guard_rearm_id_);
                    if (gb) arm_guard(*gb, current_pid_, e);
                    guard_rearm_id_ = 0;
                }
            }
            return resume_wait(timeout_ms, err);
        }
    }
    err = "unknown resume action";
    return false;
}

bool Engine::interrupt(std::string& err) {
    if (!process()) {
        err = "no active target";
        return false;
    }
    if (!DebugBreakProcess(process())) {
        err = fmt("DebugBreakProcess failed: %s", last_error_text().c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- breakpoints

bool Engine::arm_guard(Breakpoint& bp, uint32_t pid, std::string& err) {
    ProcessInfo* p = proc_by_pid(pid);
    if (!p) {
        err = "no such process";
        return false;
    }
    MemRegion reg;
    if (!region_at(p->handle, bp.address, reg)) {
        err = "cannot query region for memory breakpoint";
        return false;
    }
    DWORD old = 0;
    if (!protect_memory(p->handle, reg.base, reg.size, reg.protect | PAGE_GUARD, old, err))
        return false;
    BpPlant& pl = bp.plant_of(pid);
    pl.region_base = reg.base;
    pl.region_size = reg.size;
    pl.region_protect = reg.protect;
    pl.planted = true;
    pl.present = true;
    return true;
}

bool Engine::disarm_guard(Breakpoint& bp, uint32_t pid) {
    BpPlant& pl = bp.plant_of(pid);
    if (!pl.planted) return true;
    ProcessInfo* p = proc_by_pid(pid);
    if (!p) return true;
    DWORD old = 0;
    std::string e;
    protect_memory(p->handle, pl.region_base, pl.region_size, pl.region_protect, old, e);
    pl.planted = false;
    return true;
}

bool Engine::plant_all_hardware(std::string& err) {
    std::vector<Breakpoint*> hw;
    for (auto& bp : bps.all())
        if (bp.kind == BpKind::Hardware && bp.enabled) hw.push_back(&bp);

    // DR0-DR3 are per-thread, so every thread of every process gets the set
    for (auto& p : processes_) {
        if (!p.alive) continue;
        for (auto& t : p.threads) {
            if (!t.handle || !t.alive) continue;
            CpuState st;
            if (!aj::get_state(t.handle, p.is32, st, err)) continue;
            st.dr[0] = st.dr[1] = st.dr[2] = st.dr[3] = 0;
            st.dr7 = 0;
            for (size_t i = 0; i < hw.size() && i < 4; ++i) {
                Breakpoint* bp = hw[i];
                bp->slot = (int)i;
                st.dr[i] = bp->address;
                unsigned rw, len;
                if (bp->access & BP_ACC_WRITE) {
                    rw = 1;
                } else if (bp->access & BP_ACC_READ) {
                    rw = 3;
                } else {
                    rw = 0;
                }
                switch (bp->size) {
                    case 2: len = 1; break;
                    case 4: len = 3; break;
                    case 8: len = 2; break;
                    default: len = 0; break;
                }
                unsigned shift = 16 + (unsigned)i * 4;
                st.dr7 |= (rw << shift) | (len << (shift + 2));
                st.dr7 |= (1ULL << (i * 2));  // local enable
            }
            if (!aj::set_state(t.handle, st, err)) continue;
        }
    }
    return true;
}

bool Engine::apply_breakpoint(Breakpoint& bp, std::string& err) {
    // No live process yet: the breakpoint stays pending and is planted when the
    // target starts. Setting breakpoints before launching is a normal workflow.
    if (processes_.empty()) return true;
    switch (bp.kind) {
        case BpKind::Software: {
            bool any = false;
            for (auto& p : processes_) {
                if (!p.alive) continue;
                std::string e;
                if (bps.plant_software(p.handle, p.pid, bp, e)) {
                    any = true;
                } else if (err.empty()) {
                    err = e;
                }
            }
            return any;
        }
        case BpKind::Hardware: {
            bool ok = plant_all_hardware(err);
            if (ok && bp.slot < 0) {
                err = "no free hardware breakpoint slot (max 4)";
                return false;
            }
            return ok;
        }
        case BpKind::Memory: {
            bool any = false;
            for (auto& p : processes_) {
                if (!p.alive) continue;
                std::string e;
                if (arm_guard(bp, p.pid, e)) {
                    any = true;
                } else if (err.empty()) {
                    err = e;
                }
            }
            return any;
        }
    }
    return false;
}

bool Engine::remove_breakpoint(int id, std::string& err) {
    Breakpoint* bp = bps.find(id);
    if (!bp) {
        err = fmt("no such breakpoint: %d", id);
        return false;
    }
    BpKind kind = bp->kind;
    for (auto& kv : bp->plants) {
        ProcessInfo* p = proc_by_pid(kv.first);
        if (!p || !kv.second.planted) continue;
        if (kind == BpKind::Software)
            bps.unplant_software(p->handle, kv.first, *bp, err);
        else if (kind == BpKind::Memory)
            disarm_guard(*bp, kv.first);
    }
    bps.remove(id);
    if (kind == BpKind::Hardware) plant_all_hardware(err);
    return true;
}

bool Engine::set_breakpoint_enabled(int id, bool enabled, std::string& err) {
    Breakpoint* bp = bps.find(id);
    if (!bp) {
        err = fmt("no such breakpoint: %d", id);
        return false;
    }
    if (bp->enabled == enabled) return true;
    bp->enabled = enabled;
    if (processes_.empty()) return true;  // pending: applied when the target starts
    switch (bp->kind) {
        case BpKind::Software:
            for (auto& p : processes_) {
                if (!p.alive) continue;
                if (enabled)
                    bps.plant_software(p.handle, p.pid, *bp, err);
                else
                    bps.unplant_software(p.handle, p.pid, *bp, err);
            }
            return true;
        case BpKind::Hardware:
            return plant_all_hardware(err);
        case BpKind::Memory:
            for (auto& p : processes_) {
                if (!p.alive) continue;
                if (enabled)
                    arm_guard(*bp, p.pid, err);
                else
                    disarm_guard(*bp, p.pid);
            }
            return true;
    }
    return true;
}

void Engine::resolve_deferred_breakpoints() {
    for (auto& bp : bps.all()) {
        if (!bp.enabled) continue;

        // resolve anything still waiting for its module or symbol
        if (!bp.resolved) {
            uint64_t addr = 0;
            std::string e;
            if (!bp.symbol.empty() && eval(bp.symbol, addr, e) && addr) {
                bp.address = addr;
                bp.resolved = true;
            } else {
                continue;  // still not resolvable
            }
        }

        // every live process must carry this breakpoint
        std::string e;
        for (auto& p : processes_) {
            if (!p.alive) continue;
            if (bp.kind == BpKind::Software)
                bps.plant_software(p.handle, p.pid, bp, e);
            else if (bp.kind == BpKind::Memory)
                arm_guard(bp, p.pid, e);
        }
        if (bp.kind == BpKind::Hardware && bp.slot < 0) apply_breakpoint(bp, e);
    }
}

// ---------------------------------------------------------------- expressions

// --------------------------------------------------- module-load breakpoints

bool Engine::add_module_break(const std::string& pattern, std::string& err) {
    if (trim(pattern).empty()) {
        err = "empty pattern";
        return false;
    }
    for (const auto& p : module_breaks_)
        if (to_lower(p) == to_lower(pattern)) {
            err = "pattern already present";
            return false;
        }
    module_breaks_.push_back(pattern);
    return true;
}

bool Engine::del_module_break(const std::string& pattern, std::string& err) {
    for (size_t i = 0; i < module_breaks_.size(); ++i) {
        if (to_lower(module_breaks_[i]) == to_lower(pattern)) {
            module_breaks_.erase(module_breaks_.begin() + (long)i);
            return true;
        }
    }
    err = "no such pattern";
    return false;
}

EvalContext Engine::eval_context() {
    EvalContext ctx;
    ctx.read_reg = [this](const std::string& reg, uint64_t& out) {
        CpuState st;
        std::string e;
        if (!get_state(st, e)) return false;
        return read_reg(st, reg, out);
    };
    ctx.read_ptr = [this](uint64_t addr, uint64_t& out) {
        std::string e;
        size_t ps = pointer_size();
        uint64_t v = 0;
        size_t got = 0;
        if (!read_memory(process(), addr, &v, ps, e, &got) || got != ps) return false;
        out = v;
        return true;
    };
    ctx.resolve = [this](const std::string& name, uint64_t& out) {
        std::string e;
        // user labels first ("break my_loop")
        {
            std::string mod;
            uint64_t rva = 0;
            if (notes.lookup_label(name, mod, rva)) {
                const ModuleInfo* m = module_by_name(mod);
                if (m) {
                    out = m->base + rva;
                    return true;
                }
                return false;  // known label but module not loaded
            }
        }
        // "module+0xoff" / "module+off"
        size_t plus = name.find('+');
        if (plus != std::string::npos) {
            std::string mod = name.substr(0, plus);
            uint64_t off = 0;
            if (!parse_u64(name.substr(plus + 1), off)) return false;
            const ModuleInfo* m = module_by_name(mod);
            if (!m) return false;
            out = m->base + off;
            return true;
        }
        if (name == "$entry" || name == "entry") {
            const ProcessInfo* p = cur_proc();
            out = p ? p->entry : 0;
            return out != 0;
        }
        // "$ra" - return address of the current frame
        if (name == "$ra") {
            uint64_t ra = 0;
            std::string err2;
            if (!return_address(ra, err2)) return false;
            out = ra;
            return true;
        }
        return sym.resolve_name(name, out, e);
    };
    return ctx;
}

bool Engine::typed_eval(const std::string& expr, TypedValue& out, std::string& err) {
    if (!process()) {
        err = "no active target";
        return false;
    }
    types.init(process());
    TypedResolver r;
    r.types = &types;
    r.eval_plain = [this](const std::string& text, uint64_t& v, std::string& e) {
        return eval(text, v, e);
    };
    r.read = [this](uint64_t addr, void* buf, size_t n, std::string& e) {
        size_t got = 0;
        return read_memory(process(), addr, buf, n, e, &got) && got == n;
    };
    return resolve_typed(expr, r, out, err);
}

bool Engine::eval(const std::string& text, uint64_t& out, std::string& err) {
    std::string t = trim(text);
    if (parse_u64(t, out)) return true;

    // "module+0xoff" and "symbol+0xoff" are split into tokens by the expression
    // lexer, so resolve those forms here before falling back to the evaluator.
    size_t plus = t.find('+');
    if (plus != std::string::npos) {
        std::string head = t.substr(0, plus);
        std::string rest = t.substr(plus + 1);
        bool plain = !head.empty() && head.find_first_of("*/[]()&|^<>- ") == std::string::npos;
        uint64_t off = 0;
        if (plain && parse_u64(rest, off)) {
            if (const ModuleInfo* m = module_by_name(head)) {
                out = m->base + off;
                return true;
            }
            // the left hand side may be a symbol rather than a module
            uint64_t base_addr = 0;
            std::string e2;
            if (sym.resolve_name(head, base_addr, e2)) {
                out = base_addr + off;
                return true;
            }
            // neither? then this is plain arithmetic ("2+2", "rax+4") and the
            // general evaluator handles it
        }
    }
    return eval_expr(t, eval_context(), out, err);
}

// ---------------------------------------------------------------- callstack

Json Engine::callstack(size_t max_frames) {
    Json arr = Json::arr();
    if (!process() || !thread_handle_) return arr;
    std::string e;

    // StackWalk64 needs a context matching the target's machine type: a WOW64
    // target is walked with a 32-bit context and IMAGE_FILE_MACHINE_I386.
    STACKFRAME64 sf;
    std::memset(&sf, 0, sizeof(sf));
    DWORD machine = IMAGE_FILE_MACHINE_AMD64;
    WOW64_CONTEXT wc;
    CONTEXT ctx;
    void* ctxptr = nullptr;

    if (is32()) {
        std::memset(&wc, 0, sizeof(wc));
        wc.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(thread_handle_, &wc)) return arr;
        sf.AddrPC.Offset = wc.Eip;
        sf.AddrFrame.Offset = wc.Ebp;
        sf.AddrStack.Offset = wc.Esp;
        machine = IMAGE_FILE_MACHINE_I386;
        ctxptr = &wc;
    } else {
        std::memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(thread_handle_, &ctx)) return arr;
        sf.AddrPC.Offset = ctx.Rip;
        sf.AddrFrame.Offset = ctx.Rbp;
        sf.AddrStack.Offset = ctx.Rsp;
        ctxptr = &ctx;
    }
    sf.AddrPC.Mode = AddrModeFlat;
    sf.AddrFrame.Mode = AddrModeFlat;
    sf.AddrStack.Mode = AddrModeFlat;

    for (size_t i = 0; i < max_frames; ++i) {
        if (!StackWalk64(machine, process(), thread_handle_, &sf, ctxptr, nullptr,
                         SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
            break;
        if (!sf.AddrPC.Offset) break;

        Json f = Json::obj();
        f.set_u("index", (uint64_t)i);
        f.set_hex("address", sf.AddrPC.Offset);

        std::string name;
        uint64_t disp = 0;
        if (sym.lookup_address(sf.AddrPC.Offset, name, disp, e)) {
            f.set_str("symbol", name);
            if (disp) f.set_hex("symbol_disp", disp);
        }
        const ModuleInfo* m = module_at(sf.AddrPC.Offset);
        if (m) {
            f.set_str("module", m->name);
            f.set_hex("module_offset", sf.AddrPC.Offset - m->base);
        }
        std::string file;
        uint32_t line = 0;
        uint64_t ldisp = 0;
        if (sym.line_from_address(sf.AddrPC.Offset, file, line, ldisp)) {
            f.set_str("file", file);
            f.set_u("line", line);
        }
        f.set_hex("frame", sf.AddrFrame.Offset);
        f.set_hex("stack", sf.AddrStack.Offset);
        arr.push(std::move(f));
        if (sf.AddrPC.Offset == sf.AddrReturn.Offset) break;
    }
    return arr;
}

bool Engine::return_address(uint64_t& out, std::string& err) {
    // The return address of the current frame lives at [sp] right after a call,
    // which is where step-out is normally used from.
    CpuState st;
    if (!get_state(st, err)) return false;
    uint64_t sp = 0;
    read_reg(st, "rsp", sp);  // aliases esp on x86
    size_t ps = pointer_size();
    uint64_t ra = 0;
    size_t got = 0;
    if (!read_memory(process(), sp, &ra, ps, err, &got) || got != ps) return false;
    if (!ra) {
        err = "cannot determine return address";
        return false;
    }
    out = ra;
    return true;
}

// ---------------------------------------------------------- import tracing

bool Engine::trace_import(uint64_t from_addr, size_t max_steps, Json& report,
                          std::string& err) {
    report = Json::obj();
    err.clear();
    if (!is_paused()) {
        err = "target is not paused";
        return false;
    }
    if (!max_steps) max_steps = 2000;
    if (max_steps > 200000) max_steps = 200000;

    // ---- get to the call site ------------------------------------------
    CpuState st;
    if (!get_state(st, err)) return false;
    if (st.rip != from_addr) {
        if (!resume(ResumeAction::RunUntil, from_addr, 10000, err)) return false;
        if (stop_.reason == StopReason::Exit || !active()) {
            err = fmt("the target exited before reaching %s", hex8(from_addr).c_str());
            return false;
        }
    }

    // ---- capture state so tracing leaves no side effects ----------------
    // Auto capture is off during the trace: it would snapshot every single
    // step (megabytes each) and the restore below must go back to exactly the
    // state we started from, not to the newest capture.
    const bool prev_auto = snaps.auto_enabled();
    snaps.set_auto(false);
    std::string snap_err;
    bool captured = snapshot_save("__trace__", snap_err);

    // ---- walk the call until control reaches a real export -------------
    Json path = Json::arr();
    uint64_t api_addr = 0;
    std::string module, function;
    size_t steps = 0;
    bool resolved = false;

    while (steps < max_steps) {
        ++steps;  // count the step we are about to take
        if (!resume(ResumeAction::StepInto, 0, 0, err)) break;
        if (stop_.reason == StopReason::Exit || !active()) {
            err = "target exited while tracing";
            break;
        }
        CpuState cur;
        if (!get_state(cur, err)) break;

        Json pj = Json::obj();
        pj.set_u("step", steps);
        pj.set_hex("rip", cur.rip);
        path.push(std::move(pj));

        // the moment RIP sits on the first instruction of an export we have
        // found the real API, however opaque the route to it was
        const ModuleInfo* m = module_at(cur.rip);
        if (m) {
            Exports ex;
            ex.init(process(), m->base, m->name);
            std::string e2;
            if (ex.load(e2)) {
                ExportEntry ent;
                if (ex.find_by_address(cur.rip, ent)) {
                    api_addr = cur.rip;
                    module = m->name;
                    function = ent.name.empty()
                                   ? fmt("#%llu", (unsigned long long)ent.ordinal)
                                   : ent.name;
                    resolved = true;
                    break;
                }
            }
        }
    }

    // ---- put the target back the way we found it ----------------------
    if (captured) {
        std::string e2;
        snapshot_restore("__trace__", e2);
    }
    snaps.set_auto(prev_auto);

    report.set_bool("resolved", resolved);
    report.set_u("steps", steps);
    report.set("path", path);
    if (resolved) {
        report.set_hex("api", api_addr);
        report.set_str("module", module);
        report.set_str("function", function);
    }
    return true;
}

}  // namespace aj
