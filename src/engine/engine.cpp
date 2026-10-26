#include "engine/engine.h"

#include <dbghelp.h>
#include <psapi.h>

#include <cstring>

#include "engine/disasm.h"
#include "engine/exports.h"
#include "engine/ntview.h"
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
// file handle instead - that is always available at this point. The fixed-base
// launch renames the image file right after CreateProcess returns, and a
// query landing inside that rename window fails; without a path the module
// would register into DbgHelp nameless and its symbols would never resolve,
// so retry briefly before giving up.
std::string path_from_file_handle(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return {};
    for (int attempt = 0; attempt < 5; ++attempt) {
        wchar_t buf[MAX_PATH * 2] = {0};
        DWORD n = GetFinalPathNameByHandleW(h, buf, MAX_PATH * 2,
                                            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n && n < MAX_PATH * 2) {
            std::string p = to_utf8(buf);
            if (starts_with(p, "\\\\?\\")) p = p.substr(4);
            return p;
        }
        Sleep(10);
    }
    return {};
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
    if (!read_memory_exact(proc, base, dos, sizeof(dos), err)) return 0;
    uint32_t lfanew = *(uint32_t*)(dos + 0x3C);
    if (lfanew > 0x1000) return 0;
    uint8_t nth[4 + 20 + 0x40];
    if (!read_memory_exact(proc, base + lfanew, nth, sizeof(nth), err)) return 0;
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

// IMAGE_DLLCHARACTERISTICS flags that make the kernel relocate the image.
constexpr uint16_t kDynamicBase = 0x0040;
constexpr uint16_t kHighEntropyVa = 0x0020;

static bool patch_file_flag(const std::wstring& path, size_t offset, uint8_t lo, uint8_t hi) {
    HANDLE w = CreateFileW(path.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (w == INVALID_HANDLE_VALUE) return false;
    uint8_t nb[2] = {lo, hi};
    DWORD got = 0;
    SetFilePointer(w, (LONG)offset, nullptr, FILE_BEGIN);
    BOOL ok = WriteFile(w, nb, 2, &got, nullptr) && got == 2;
    CloseHandle(w);
    return ok != FALSE;
}

// PE basics straight from the file: machine, entry point RVA, DLL flag.
bool pe_file_basics(const std::wstring& path, uint16_t& machine, uint32_t& entry_rva,
                    bool& is_dll) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint8_t hdr[0x60];
    DWORD got = 0;
    bool ok = false;
    uint32_t lfanew = 0;
    do {
        if (!ReadFile(h, hdr, sizeof(hdr), &got, nullptr) || got != sizeof(hdr)) break;
        lfanew = *(uint32_t*)(hdr + 0x3C);
        if (lfanew > 0x1000) break;
        uint8_t nth[4 + 20 + 0x18];
        SetFilePointer(h, (LONG)lfanew, nullptr, FILE_BEGIN);
        if (!ReadFile(h, nth, sizeof(nth), &got, nullptr) || got != sizeof(nth)) break;
        if (*(uint32_t*)nth != 0x00004550) break;
        machine = *(uint16_t*)(nth + 4);
        uint16_t characteristics = *(uint16_t*)(nth + 4 + 18);
        is_dll = (characteristics & 0x2000) != 0;  // IMAGE_FILE_DLL
        const uint8_t* opt = nth + 4 + 20;
        uint16_t magic = *(uint16_t*)opt;
        if (magic != 0x10B && magic != 0x20B) break;
        entry_rva = *(uint32_t*)(opt + 0x10);
        ok = true;
    } while (false);
    CloseHandle(h);
    return ok;
}

// Extracts the embedded DLL-host stub (both architectures live in aidbg's
// resources - a 64-bit process cannot load a 32-bit DLL).
bool extract_dll_host(bool want32, std::wstring& out, std::string& err) {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    out = std::wstring(tmp) + L"aidbg-dhost-" + std::to_wstring(GetCurrentProcessId()) +
          (want32 ? L"-32.exe" : L"-64.exe");
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC res = FindResourceW(self, MAKEINTRESOURCEW(want32 ? 102 : 101), MAKEINTRESOURCEW(10) /*RT_RCDATA*/);
    if (!res) {
        err = "DLL host stub resource is missing from this build";
        return false;
    }
    HGLOBAL h = LoadResource(self, res);
    DWORD size = SizeofResource(self, res);
    const void* data = LockResource(h);
    if (!h || !data || !size) {
        err = "cannot read the DLL host stub resource";
        return false;
    }
    HANDLE f = CreateFileW(out.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        err = fmt("cannot extract the DLL host stub: %s", last_error_text().c_str());
        return false;
    }
    DWORD wrote = 0;
    BOOL ok = WriteFile(f, data, size, &wrote, nullptr) && wrote == size;
    CloseHandle(f);
    if (!ok) {
        err = "cannot write the DLL host stub";
        DeleteFileW(out.c_str());
        return false;
    }
    return true;
}

// The fixed-base swap renames the target file aside; that must never be tried
// on operating system files (they cannot - and must not - be moved).
bool is_system_path(const std::wstring& path) {
    wchar_t sys[MAX_PATH], win[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring p = path;
    std::wstring s = sys, w = win;
    auto starts = [](const std::wstring& a, const std::wstring& b) {
        return a.size() >= b.size() && _wcsicmp(a.substr(0, b.size()).c_str(), b.c_str()) == 0;
    };
    return starts(p, s + L"\\") || starts(p, w + L"\\");
}

// Prepares a fixed-base launch WITHOUT ever writing the target's own bytes:
// the original file is renamed aside (bytes untouched), a patched copy takes
// its place for the CreateProcess call, and revert() swaps the original back
// before the target can execute - so the path the target sees (and hashes, in
// a self-check) holds exactly the original file again. Windows refuses to
// write, replace or delete a running image's file, but plain renames of
// running images are allowed - which is what the swap relies on.
// Deletes staging copies of an earlier launch. A file whose image is still
// mapped cannot be deleted (sharing violation) and is simply left for later;
// that is why each launch uses a fresh, unique staging name.
static void cleanup_staged_files(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    std::wstring dir = slash == std::wstring::npos ? std::wstring() : path.substr(0, slash + 1);
    std::wstring pat = path + L".aidbg-patched*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        DeleteFileW((dir + fd.cFileName).c_str());
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

bool TransientPePatch::clear_dynamic_base(const std::wstring& path) {
    target = path;
    orig = path + L".aidbg-orig";
    // Unique per launch: a previous session may still have its image mapped,
    // and renaming onto that existing name fails (win32 error 183), leaving
    // the user's file patched.
    staged = path + L".aidbg-patched-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
             std::to_wstring(GetTickCount64());

    cleanup_staged_files(path);
    // Recover from a previous crash mid-swap: when .aidbg-orig exists it holds
    // the pristine file and the path may hold a patched copy - without this the
    // user's file would stay modified forever (and defeat its own self-check).
    if (GetFileAttributesW(orig.c_str()) != INVALID_FILE_ATTRIBUTES) {
        MoveFileExW(path.c_str(), staged.c_str(), 0);  // path may be the patched copy
        if (!MoveFileExW(orig.c_str(), path.c_str(), 0)) {
            err = fmt("cannot restore the original from %s: %s", to_utf8(orig).c_str(),
                      last_error_text().c_str());
            return false;
        }
        DeleteFileW(staged.c_str());
    }

    // locate DllCharacteristics without touching the file
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = fmt("cannot open '%s': %s", to_utf8(path).c_str(), last_error_text().c_str());
        return false;
    }
    uint8_t hdr[0x60];
    DWORD got = 0;
    uint32_t lfanew = 0;
    uint16_t dllch = 0, cleared = 0;
    size_t field_offset = 0;
    bool ok = false;
    do {
        if (!ReadFile(h, hdr, sizeof(hdr), &got, nullptr) || got != sizeof(hdr)) break;
        lfanew = *(uint32_t*)(hdr + 0x3C);
        if (lfanew > 0x1000) break;
        if (SetFilePointer(h, (LONG)lfanew + 24, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            break;
        uint8_t opt[0x48];
        if (!ReadFile(h, opt, sizeof(opt), &got, nullptr) || got != sizeof(opt)) break;
        uint16_t magic = *(uint16_t*)opt;
        if (magic != 0x10B && magic != 0x20B) break;
        dllch = *(uint16_t*)(opt + 0x46);
        cleared = (uint16_t)(dllch & ~(kDynamicBase | kHighEntropyVa));
        field_offset = (size_t)lfanew + 24 + 0x46;
        ok = true;
    } while (false);
    CloseHandle(h);
    if (!ok) {
        err = "bad PE image (cannot locate DllCharacteristics)";
        return false;
    }
    if (cleared == dllch) return true;  // already honours the ImageBase

    // leftovers of an earlier crashed run are not in use now
    DeleteFileW(orig.c_str());
    DeleteFileW(staged.c_str());

    // 1) the original is renamed aside - its bytes are never touched
    if (!MoveFileExW(path.c_str(), orig.c_str(), 0)) {
        err = fmt("cannot move the original aside: %s", last_error_text().c_str());
        return false;
    }
    // 2) a copy takes the path and only that copy is patched
    if (!CopyFileW(orig.c_str(), path.c_str(), FALSE) ||
        !patch_file_flag(path, field_offset, (uint8_t)cleared, (uint8_t)(cleared >> 8))) {
        err = fmt("cannot prepare the patched copy: %s", last_error_text().c_str());
        DeleteFileW(path.c_str());
        MoveFileExW(orig.c_str(), path.c_str(), 0);  // roll back
        return false;
    }
    patched = true;
    return true;
}

void TransientPePatch::revert() {
    if (patched) {
        // The running image keeps its file object no matter the name, so the
        // patched copy is renamed away and the pristine original takes the
        // path back - before the target has executed a single instruction.
        bool restored = false;
        if (MoveFileExW(target.c_str(), staged.c_str(), 0)) {
            restored = MoveFileExW(orig.c_str(), target.c_str(), 0) != FALSE;
            if (!restored) MoveFileExW(staged.c_str(), target.c_str(), 0);  // roll back
        }
        if (!restored) {
            err = fmt("RESTORE FAILED (%s) - the target path still holds the patched file; "
                      "the pristine copy is at %s",
                      last_error_text().c_str(), to_utf8(orig).c_str());
            return;
        }
        patched = false;
        // the renamed-away patched image can only be deleted once the target
        // has exited; leftovers are cleaned up on the next fixed-base launch
        if (!DeleteFileW(staged.c_str()))
            err = fmt("note: '%s' stays until the target exits (its image is still mapped)",
                      to_utf8(staged).c_str());
    }
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
        if (p.alive && !p.is_system) {
            current_pid_ = p.pid;
            sym.select(p.pid);
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
    sym.select(pid);
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
    // A session whose target already exited must not block the next launch.
    // Leftover entries (and a former conhost) are cleaned up first.
    if (!active() && !processes_.empty()) reset_session();
    if (active()) {
        err = "a target is already active; detach or kill it first";
        return false;
    }
    std::wstring wexe = to_wide(exe);
    std::wstring cmdline = L"\"" + wexe + L"\"";
    if (!args.empty()) cmdline += L" " + to_wide(args);

    // ---- DLL targets run inside an embedded host stub ---------------------
    // A DLL cannot be created as a process. The stub loads it (which runs its
    // DllMain) and optionally calls one export; for a DLL target `args` means
    // "[export]".
    std::wstring dll_path;  // non-empty when the target is a DLL
    std::string dll_export;
    uint32_t dll_entry = 0;
    std::wstring launch_exe = wexe;
    if (is_dll_image(wexe)) {
        uint16_t machine = 0;
        bool is_dll = false;
        if (!pe_file_basics(wexe, machine, dll_entry, is_dll)) {
            err = "bad PE image: " + exe;
            return false;
        }
        dll_path = wexe;
        dll_export = trim(args);
        std::string e2;
        if (!extract_dll_host(machine == 0x14C, dll_host_stub_, e2)) {
            err = e2;
            return false;
        }
        launch_exe = dll_host_stub_;
        cmdline = L"\"" + dll_host_stub_ + L"\" \"" + wexe + L"\"";
        if (!dll_export.empty()) cmdline += L" \"" + to_wide(dll_export) + L"\"";
    }

    // The debuggee's stdout must never interleave with our JSON stream, so by
    // default it gets no console at all. Use --console when its output matters.
    // DEBUG_PROCESS also reports processes the target spawns; DEBUG_ONLY_THIS_PROCESS
    // keeps the session to a single process.
    DWORD flags = (follow_children ? DEBUG_PROCESS : DEBUG_ONLY_THIS_PROCESS) |
                  (new_console ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);

    // Turning ASLR off makes the image live at the PE ImageBase, so the runtime
    // addresses line up with what a static disassembler shows (0x140000000 for
    // x64, 0x400000 for x86 by default). The DYNAMIC_BASE flag is cleared in
    // the file's in-memory pages before CreateProcess and restored right after
    // it returns: the kernel builds the image section from those pages, so the
    // image loads at the preferred base by itself while the file on disk (and
    // any self-check the target performs on it) stays byte-identical. For a DLL
    // target the swap must stay active until the loader maps the DLL, so it
    // lives in dll_patch_ and is reverted at the LOAD_DLL event.
    exe_patch_ = TransientPePatch{};  // fresh swap state for this launch
    bool pin_base = fixed_base;
    if (pin_base && is_system_path(dll_path.empty() ? wexe : dll_path)) {
        // never rename operating system files aside, not even briefly
        Output::instance().event("warning",
                                 "fixed base skipped for a system file, loading with ASLR",
                                 Json::obj());
        pin_base = false;
    }
    if (pin_base) {
        TransientPePatch& target_patch = dll_path.empty() ? exe_patch_ : dll_patch_;
        if (!target_patch.clear_dynamic_base(dll_path.empty() ? wexe : dll_path)) {
            // fall back to a normal (relocated) launch instead of failing:
            // the session still works, `modules` shows a non-zero slide
            Json d = Json::obj();
            d.set_str("reason", target_patch.err);
            Output::instance().event(
                "warning", "fixed base unavailable, continuing with ASLR (slide will be "
                           "non-zero; add --aslr to silence this)",
                d);
        }
    }

    STARTUPINFOW si;
    std::memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    std::memset(&pi, 0, sizeof(pi));
    std::wstring wcwd = cwd.empty() ? std::wstring() : to_wide(cwd);
    // remember what we are launching: the CREATE_PROCESS event sometimes
    // carries a NULL file handle, and this is then the only path source for
    // the main module (see on_create_process)
    {
        wchar_t full[MAX_PATH * 2];
        DWORD n = GetFullPathNameW(launch_exe.c_str(), MAX_PATH * 2, full, nullptr);
        launch_exe_path_ = (n && n < MAX_PATH * 2) ? std::wstring(full) : launch_exe;
    }
    BOOL ok = CreateProcessW(launch_exe.c_str(), cmdline.data(), nullptr, nullptr, FALSE, flags,
                             nullptr, wcwd.empty() ? nullptr : wcwd.c_str(), &si, &pi);
    DWORD create_err = ok ? 0 : GetLastError();
    if (dll_path.empty()) exe_patch_.revert();  // pristine bytes again before the target sees them
    if (dll_path.empty() && !exe_patch_.err.empty()) {
        // a failed restore leaves the user's file patched - shout about it
        Output::instance().event("error", exe_patch_.err, Json::obj());
        std::fprintf(stderr, "[aidbg] %s\n", exe_patch_.err.c_str());
        std::fflush(stderr);
    }
    if (!ok) {
        dll_patch_.revert();
        err = fmt("CreateProcess(%s) failed: %s", exe.c_str(), last_error_text(create_err).c_str());
        return false;
    }

    // The CREATE_PROCESS event hands us the handles to keep; drop these.
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // Debug the DLL itself: stop when it is mapped, then at its entry point
    // (DllMain). Both are pending breakpoints - they resolve on the load.
    if (!dll_path.empty()) {
        std::string dllname = base_name_of(to_utf8(dll_path));
        std::string e2;
        add_module_break(dllname, e2);
        Breakpoint bp;
        bp.kind = BpKind::Software;
        bp.symbol = dllname + "+0x" + hex_no_prefix(dll_entry);
        bp.resolved = false;
        bps.add(bp);
    }

    stop_at_entry_ = true;
    awaiting_entry_ = true;
    stop_ = StopInfo{};
    // pump the debug loop until the first meaningful stop (the entry breakpoint)
    return wait_for_stop(0, err);
}

bool Engine::is_dll_image(const std::wstring& path) {
    uint16_t machine = 0;
    uint32_t entry = 0;
    bool is_dll = false;
    return pe_file_basics(path, machine, entry, is_dll) && is_dll;
}

bool Engine::attach(uint32_t pid, std::string& err) {
    if (!active() && !processes_.empty()) reset_session();
    if (active()) {
        err = "a target is already active; detach or kill it first";
        return false;
    }
    if (!DebugActiveProcess(pid)) {
        err = fmt("DebugActiveProcess(%u) failed: %s", pid, last_error_text().c_str());
        return false;
    }
    DebugSetProcessKillOnExit(FALSE);
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
    if (in_hit_command_) {
        err = "detach is not allowed from a breakpoint on-hit command";
        return false;
    }
    if (processes_.empty()) {
        err = "no active target";
        return false;
    }
    // restore any planted breakpoints so the targets keep working
    hide.unplant_all();  // ntdll hook INT3s must not survive the detach
    dll_patch_.revert();  // a DLL base swap must not outlive the session
    for (auto& bp : bps.all()) {
        if (bp.kind == BpKind::Software) {
            for (auto& kv : bp.plants) {
                ProcessInfo* p = proc_by_pid(kv.first);
                if (p && kv.second.planted) bps.unplant_software(p->handle, kv.first, bp, err);
            }
        } else if (bp.kind == BpKind::Memory) {
            for (auto& kv : bp.plants) {
                if (!kv.second.planted) continue;
                ProcessInfo* p = proc_by_pid(kv.first);
                if (!p) continue;
                DWORD old = 0;
                protect_memory(p->handle, kv.second.region_base, kv.second.region_size,
                               kv.second.region_protect, old, err);
                kv.second.planted = false;
            }
        }
    }

    continue_pending(pending_status_);
    for (auto& p : processes_)
        if (p.alive) DebugActiveProcessStop(p.pid);
    hide.reset();
    bps.forget_plants();
    sym.shutdown();
    symbols_ready_ = false;
    snaps.clear();
    release_all(processes_);
    current_pid_ = 0;
    current_tid_ = 0;
    thread_handle_ = nullptr;
    has_pending_ = false;
    at_bp_id_ = 0;
    replant_pending_ = 0;
    temp_bp_id_ = 0;
    guard_rearm_id_ = 0;
    silent_step_ = false;
    hw_silent_slot_ = -1;
    at_hw_slot_ = -1;
    stop_ = StopInfo{};
    return true;
}

bool Engine::kill(std::string& err) {
    if (in_hit_command_) {
        err = "kill is not allowed from a breakpoint on-hit command";
        return false;
    }
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
    dll_patch_.revert();  // a DLL base swap must not outlive the session
    continue_pending(pending_status_);
    for (auto& p : processes_)
        if (p.alive) TerminateProcess(p.handle, 1);
    // drain remaining events so the debug session ends cleanly
    DEBUG_EVENT ev;
    for (int i = 0; i < 256; ++i) {
        if (!WaitForDebugEvent(&ev, 200)) break;
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
    hide.reset();
    bps.forget_plants();
    sym.shutdown();
    symbols_ready_ = false;
    snaps.clear();
    release_all(processes_);
    current_pid_ = 0;
    current_tid_ = 0;
    thread_handle_ = nullptr;
    has_pending_ = false;
    at_bp_id_ = 0;
    replant_pending_ = 0;
    temp_bp_id_ = 0;
    guard_rearm_id_ = 0;
    silent_step_ = false;
    hw_silent_slot_ = -1;
    at_hw_slot_ = -1;
    stop_ = StopInfo{StopReason::Exit, "process terminated"};
    return true;
}

bool Engine::any_live_target() const {
    for (const auto& p : processes_)
        if (p.alive && !p.is_system) return true;
    return false;
}

uint64_t Engine::bp_address_for(const Breakpoint& bp, const ProcessInfo& p) {
    // "module+0xoff" style symbols resolve against *this* process's module
    // table. Private modules can be loaded at different bases in child
    // processes, so a single absolute address would plant the INT3 in the
    // wrong place. DbgHelp symbols stay absolute (system DLLs share a base).
    if (bp.symbol.empty()) return bp.address;
    size_t plus = bp.symbol.find('+');
    if (plus == std::string::npos) return bp.address;
    std::string head = bp.symbol.substr(0, plus);
    uint64_t off = 0;
    if (!parse_u64(bp.symbol.substr(plus + 1), off)) return bp.address;
    std::string want = to_lower(head);
    for (const auto& m : p.modules) {
        std::string name = to_lower(m.name);
        std::string stem = name;
        size_t dot = stem.find_last_of('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        if (name == want || stem == want) return m.base + off;
    }
    return bp.address;
}

void Engine::reset_session() {
    if (in_hit_command_) return;
    // Let the target run once more before dropping its handles: a breakpoint
    // stop must be continued, an exit event must still be acknowledged.
    continue_pending(pending_status_);
    pending_status_ = kContinue;
    hide.unplant_all();
    hide.reset();
    dll_patch_.revert();  // a DLL base swap must not outlive the session
    // Remember the paths so staging copies can be removed once the image is
    // no longer mapped (the process handle is closed below).
    std::vector<std::wstring> exe_paths;
    for (auto& p : processes_)
        if (!p.is_system && !p.exe_path.empty()) exe_paths.push_back(to_wide(p.exe_path));
    // SymCleanup needs a live process handle (detach/kill do the same); doing
    // it after CloseHandle left DbgHelp's session behind, and a later handle
    // reusing the same value could collide with the stale state.
    sym.shutdown();
    symbols_ready_ = false;
    for (auto& p : processes_) {
        if (p.alive) DebugActiveProcessStop(p.pid);
        for (auto& t : p.threads)
            if (t.handle) CloseHandle(t.handle);
        if (p.handle) CloseHandle(p.handle);
    }
    processes_.clear();
    for (auto& w : exe_paths) cleanup_staged_files(w);
    bps.forget_plants();
    // one-shot breakpoints belonging to the old session
    for (int i = (int)bps.all().size() - 1; i >= 0; --i)
        if (bps.all()[i].temporary) bps.remove(bps.all()[i].id);
    snaps.clear();
    current_pid_ = 0;
    current_tid_ = 0;
    thread_handle_ = nullptr;
    at_bp_id_ = 0;
    replant_pending_ = 0;
    temp_bp_id_ = 0;
    guard_rearm_id_ = 0;
    silent_step_ = false;
    hw_silent_slot_ = -1;
    at_hw_slot_ = -1;
}

SessionMeta Engine::session_meta() const {
    SessionMeta m;
    m.active = active();
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
    m.process_count = 0;
    for (const auto& p : processes_)
        if (!p.is_system) ++m.process_count;
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
    for (const auto& p : processes_) {
        if (p.is_system) continue;
        for (const auto& m : p.modules)
            if (addr >= m.base && addr < m.base + m.size) return &m;
    }
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
    for (const auto& p : processes_) {
        if (p.is_system) continue;
        for (const auto& m : p.modules)
            if (matches(m)) return &m;
    }
    return nullptr;
}

// ---------------------------------------------------------------- events

void Engine::continue_pending(DWORD status) {
    if (has_pending_) {
        thaw_world();
        ContinueDebugEvent(pending_.dwProcessId, pending_.dwThreadId, status);
        has_pending_ = false;
    }
}

void Engine::freeze_world() {
    if (world_frozen_) return;
    world_frozen_ = true;
    for (auto& p : processes_) {
        if (!p.alive || p.is_system) continue;
        for (auto& t : p.threads)
            if (t.alive && t.handle) SuspendThread(t.handle);
    }
}

void Engine::thaw_world() {
    if (!world_frozen_) return;
    world_frozen_ = false;
    for (auto& p : processes_) {
        if (!p.alive || p.is_system) continue;
        for (auto& t : p.threads)
            if (t.alive && t.handle) ResumeThread(t.handle);
    }
}

bool Engine::wait_for_stop(uint32_t timeout_ms, std::string& err) {
    // The timeout is a wall-clock budget for the whole stop, not just for one
    // WaitForDebugEvent call: internal events (hide hook breakpoints) arrive
    // continuously and used to reset the timer, so `continue 500` never
    // returned while a hooked target was busy.
    const ULONGLONG start = GetTickCount64();
    while (true) {
        if (!has_pending_) {
            DWORD t = INFINITE;
            if (timeout_ms) {
                ULONGLONG elapsed = GetTickCount64() - start;
                if (elapsed >= timeout_ms) {
                    stop_ = StopInfo{StopReason::Timeout, "timed out waiting for a debug event"};
                    err = fmt("timeout after %u ms", timeout_ms);
                    return false;
                }
                t = (DWORD)(timeout_ms - elapsed);
            }
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
        if (stop) {
            freeze_world();  // other debuggees must not run while we inspect
            if (hw_silent_slot_ >= 0) {
                // We stopped for something other than the expected internal
                // single step: re-arm the execution breakpoint slot now so it
                // is not silently left disabled.
                hw_silent_slot_ = -1;
                std::string e2;
                plant_all_hardware(e2);
            }
            return true;  // left pending: the debuggee is frozen here
        }
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
    // Every event belongs to one process/thread pair: adopt it as current so
    // follow-up commands inspect exactly what just stopped. OS helpers such
    // as conhost.exe are followed (they inherit the debug object) but must
    // never become "the target" or steal the current process.
    ProcessInfo* ep = proc_by_pid(ev.dwProcessId);
    if (ep && !ep->is_system) {
        current_pid_ = ev.dwProcessId;
        current_tid_ = ev.dwThreadId;
        sym.select(ev.dwProcessId);
        sync_thread_handle();
    }

    switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: on_create_process(ev); break;
        case EXIT_PROCESS_DEBUG_EVENT: {
            ProcessInfo* xp = proc_by_pid(ev.dwProcessId);
            const bool system_exit = xp && xp->is_system;
            const bool target_exit = xp && !xp->is_system;
            on_exit_process(ev);
            if (system_exit || !target_exit) {
                stop = false;  // conhost / stray event: the session is unaffected
                break;
            }
            bool any_alive = false;
            for (auto& p : processes_)
                if (p.alive && !p.is_system) any_alive = true;
            stop = !any_alive;  // a surviving child keeps the session alive
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
                    // the target controls the length; it may not be
                    // NUL-terminated inside that window
                    buf.resize(strnlen(buf.c_str(), buf.size()));
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

// The fixed-base swap renames its patched copy aside right after
// CreateProcess returns, so a handle-based path query for the running image
// then reports the staged name ("app.exe.aidbg-patched-<pid>-<tick>").
// Users, notes and patches must all see the real file instead. The staged
// name embeds the pid and a tick, so matching on the file name alone cannot
// hit anything else.
void Engine::normalize_swap_path(std::string& path) const {
    auto swapped = [&](const TransientPePatch& p) {
        return !p.staged.empty() &&
               to_lower(base_name_of(path)) ==
                   to_lower(base_name_of(to_utf8(p.staged)));
    };
    if (swapped(exe_patch_)) {
        // launch_exe_path_ is the fully qualified path of what we launched
        path = launch_exe_path_.empty() ? to_utf8(exe_patch_.target)
                                        : to_utf8(launch_exe_path_);
    } else if (swapped(dll_patch_)) {
        // keep the resolved directory, restore the real file name
        std::string dir = path.substr(0, path.size() - base_name_of(path).size());
        path = dir + base_name_of(to_utf8(dll_patch_.target));
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
    if (m.path.empty() && !p.is_child && !launch_exe_path_.empty())
        m.path = to_utf8(launch_exe_path_);  // NULL hFile fallback: we know what we launched
    normalize_swap_path(m.path);
    if (!m.preferred_base) m.preferred_base = pe_image_base_path(to_wide(m.path));
    m.name = base_name_of(m.path);
    p.modules.push_back(m);
    p.exe_name = m.name;
    p.exe_path = m.path;
    // console host processes are created by csrss on the target's behalf and
    // inherit its debug port; they are debugged but are not the target
    p.is_system = (to_lower(m.name) == "conhost.exe");

    if (i.hFile) CloseHandle(i.hFile);

    ThreadInfo t;
    t.tid = ev.dwThreadId;
    t.handle = i.hThread;
    t.entry = (uint64_t)i.lpStartAddress;
    p.threads.push_back(t);

    processes_.push_back(std::move(p));
    ProcessInfo& np = processes_.back();
    if (!np.is_system) {
        current_pid_ = np.pid;
        current_tid_ = ev.dwThreadId;
        sym.select(np.pid);
        sync_thread_handle();
    }

    std::string e;
    if (!np.is_system) {
        // one DbgHelp session per process: private modules can live at
        // different bases in each child, a shared session mixed them up
        if (sym.init(np.pid, np.handle, "", e)) symbols_ready_ = true;
        sym.load_module(np.pid, m.base, (size_t)m.size, m.path, m.name, e);
    }

    // breakpoints the session already knows about must appear in this process too
    resolve_deferred_breakpoints();

    // anti-anti-debug: PEB patches first (before the target can observe them),
    // hook INT3s once ntdll shows up. Doing this to conhost would plant INT3
    // in the system console host and pollute the session.
    if (!np.is_system) hide.on_process(np.pid, np.handle, np.is32);

    // only the process the user launched gets the entry-point stop
    if (stop_at_entry_ && !np.is_system && np.entry) {
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
    uint32_t pid = ev.dwProcessId;
    ProcessInfo* p = proc_by_pid(pid);
    if (p) p->alive = false;
    hide.on_process_exit(pid);

    // An OS helper (conhost) exiting says nothing about the user's session.
    if (p && p->is_system) return;
    if (!p && !any_live_target()) {
        // Event for an already-reset session: nothing left to report.
        return;
    }

    exit_code_ = ev.u.ExitProcess.dwExitCode;
    if (any_live_target()) {
        Json d = Json::obj();
        d.set_u("pid", pid);
        d.set_u("exit_code", exit_code_);
        Output::instance().event("process_exit",
                                 fmt("process %u exited with code %u", pid, exit_code_), d);
        pick_live_process();
    } else {
        stop_ = StopInfo{StopReason::Exit, fmt("process exited with code %u", exit_code_)};
        stop_.exit_code = exit_code_;
        // End the session completely. Without this, processes_ keeps a dead
        // entry: kill/detach say "no_target" (active() is false) while launch
        // says "already active" (processes_ is not empty) - a deadlock.
        reset_session();
    }
}

void Engine::on_load_dll(DEBUG_EVENT& ev, bool& stop) {
    ProcessInfo* p = proc_by_pid(ev.dwProcessId);
    if (!p) return;
    // Late path resolution: a CREATE_PROCESS event with a NULL file handle
    // (or a child whose exe was not in its PEB list yet) leaves the main
    // module nameless, which also starves its symbol session. By the first
    // LOAD_DLL the loader has linked the exe, so try again now.
    if (!p->is_system && !p->modules.empty() && p->modules.front().path.empty()) {
        std::string got = module_name_from_base(p->handle, p->modules.front().base);
        if (!got.empty()) {
            ModuleInfo& main = p->modules.front();
            main.path = got;
            main.name = base_name_of(got);
            if (!main.preferred_base)
                main.preferred_base = pe_image_base_path(to_wide(got));
            p->exe_name = main.name;
            p->exe_path = main.path;
            std::string e2;
            sym.load_module(p->pid, main.base, (size_t)main.size, main.path, main.name, e2);
        }
    }
    LOAD_DLL_DEBUG_INFO& i = ev.u.LoadDll;
    uint64_t base = (uint64_t)i.lpBaseOfDll;
    ModuleInfo m;
    m.base = base;
    m.entry = base;
    m.size = pe_image_size(p->handle, base);
    m.preferred_base = pe_image_base_file(i.hFile);
    m.path = path_from_file_handle(i.hFile);
    if (m.path.empty()) m.path = module_name_from_base(p->handle, base);
    normalize_swap_path(m.path);
    if (!m.preferred_base) m.preferred_base = pe_image_base_path(to_wide(m.path));
    m.name = base_name_of(m.path);
    p->modules.push_back(m);
    if (i.hFile) CloseHandle(i.hFile);

    // conhost and friends: remember their module list for `ps`, nothing else
    if (p->is_system) return;

    std::string e;
    sym.load_module(p->pid, m.base, (size_t)m.size, m.path, m.name, e);
    resolve_deferred_breakpoints();
    hide.on_module_loaded(p->pid, p->handle, p->is32, m.name);

    // the fixed-base swap for a DLL target can end now that the loader has
    // mapped it: the path gets its pristine file back
    if (dll_patch_.patched && to_lower(m.path) == to_lower(to_utf8(dll_patch_.target)))
        dll_patch_.revert();

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
    ProcessInfo* p = proc_by_pid(ev.dwProcessId);
    if (!p) return;
    if (!p->is_system) sym.unload_module(p->pid, base);
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

    // WOW64 reports the x86 equivalents with their own codes; treat them exactly
    // like the native breakpoint / single-step exceptions.
    uint32_t norm = code;
    if (norm == 0x4000001F)
        norm = EXCEPTION_BREAKPOINT;
    else if (norm == 0x4000001E)
        norm = EXCEPTION_SINGLE_STEP;

    // Events from OS helpers (conhost.exe) must never be interpreted as ours:
    // system DLLs live at the same addresses in every process, so the target's
    // planted INT3 would otherwise be blamed on / unplanted from the helper.
    ProcessInfo* ep = proc_by_pid(ev.dwProcessId);
    if (ep && ep->is_system) {
        stop = false;
        status = (norm == EXCEPTION_BREAKPOINT || norm == EXCEPTION_SINGLE_STEP) ? kContinue
                                                                                : kNotHandled;
        return;
    }

    policy.note_hit(code);

    // ---- single step ----
    if (norm == EXCEPTION_SINGLE_STEP) {
        CpuState st;
        std::string e;
        bool have_state = get_state(st, e);
        // A hardware breakpoint sets a bit in DR6. Only the breakpoint that
        // owns that slot is reported; anything else is swallowed as internal.
        if (have_state && (st.dr6 & 0x0F)) {
            uint32_t dr6 = (uint32_t)st.dr6;
            st.dr6 = 0;
            set_state(st, e);
            if (replant_pending_) replant_if_pending();
            if (guard_rearm_id_) {
                Breakpoint* gb = bps.find(guard_rearm_id_);
                if (gb) arm_guard(*gb, current_pid_, e);
                guard_rearm_id_ = 0;
            }
            handle_hardware_breakpoint(ev.dwThreadId, dr6, stop);
            status = kContinue;
            return;  // false match: keep running (stop stays false)
        }
        // A pass-through hook (NtClose and friends) replants its INT3 here and
        // the step itself must stay invisible to the user. Bookkeeping that
        // belongs to the engine is handled first so it is never skipped.
        if (replant_pending_) replant_if_pending();
        if (guard_rearm_id_) {
            Breakpoint* gb = bps.find(guard_rearm_id_);
            if (gb) arm_guard(*gb, current_pid_, e);
            guard_rearm_id_ = 0;
        }
        if (hide.on_single_step()) {
            stop = false;
            status = kContinue;
            return;
        }
        if (silent_step_) {
            silent_step_ = false;
            if (hw_silent_slot_ >= 0) {
                // Re-arm the execution breakpoint disabled for this step.
                hw_silent_slot_ = -1;
                std::string e2;
                plant_all_hardware(e2);
            }
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
        // a user breakpoint at this address always wins over the hiding hooks:
        // `break ntdll!NtClose` must still fire when NtClose is hooked
        Breakpoint* bp = bps.at_address_for_pid(addr, ev.dwProcessId);
        if (bp && bp->plant_of(ev.dwProcessId).planted) {
            if (handle_software_breakpoint(addr, bp, stop)) {
                status = kContinue;
                return;
            }
            status = kContinue;
            return;
        }
        // anti-anti-debug hook sites answer the call themselves and the target
        // keeps running; they must never surface as a breakpoint hit
        if (hide.on_breakpoint(addr, stop)) {
            status = kContinue;
            return;
        }
        // our own DebugBreakProcess injection (Engine::pause): the exception
        // comes from ntdll!DbgBreakPoint and must always surface, even in a
        // child process whose loader breakpoints are being skipped
        if (ev.dwProcessId == expecting_break_pid_) {
            expecting_break_pid_ = 0;
            stop_ = StopInfo{StopReason::SystemBreak, "paused by request"};
            stop_.code = code;
            stop_.address = addr;
            stop_.first_chance = first_chance;
            stop = true;
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
        uint32_t access_kind = (uint32_t)er.ExceptionInformation[0];
        if (handle_guard_breakpoint(access_addr, access_kind, stop)) {
            status = kContinue;
            return;
        }
        // not one of our armed regions: the target installed this guard page
        // itself, so the exception belongs to it
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
    const bool clean = bps.unplant_software(process(), current_pid_, *bp, e);
    CpuState st;
    if (get_state(st, e)) {
        // Only rewind onto the instruction when its original byte is back.
        // With the 0xCC still in place, rewinding would re-hit the same
        // breakpoint forever; leave the pointer past it (where the exception
        // put it) and stop with an explanation instead.
        if (clean) {
            st.rip = addr;
            set_state(st, e);
        }
    }
    if (!clean) {
        stop_ = StopInfo{StopReason::SystemBreak,
                         fmt("cannot restore the original byte at %s; breakpoint %d stays armed "
                             "and the next instruction byte was skipped",
                             hex8(addr).c_str(), bp_id)};
        stop_.address = addr;
        stop = true;
        return true;
    }
    bp->hit_count++;
    at_bp_id_ = bp_id;
    if (!bp_command.empty() && command_hook_) {
        in_hit_command_ = true;
        command_hook_(bp_command);
        in_hit_command_ = false;
    }

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

bool Engine::handle_hardware_breakpoint(uint32_t /*tid*/, uint32_t dr6, bool& stop) {
    // DR6 bits 0..3 identify which DR0..DR3 slot matched. Reporting every
    // hardware breakpoint (as the old code did) attributes a hit to the wrong
    // id and inflates hit counts when more than one is armed.
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Hardware || !bp.enabled) continue;
        if (bp.slot < 0 || !(dr6 & (1u << bp.slot))) continue;
        bool should_stop = true;
        std::string e;
        if (!bp.command.empty() && command_hook_) {
            in_hit_command_ = true;
            command_hook_(bp.command);
            in_hit_command_ = false;
        }
        evaluate_condition(bp, should_stop, e);
        bp.hit_count++;
        if (!should_stop) {
            // The triggering instruction has not executed yet. Single-step
            // over it; an execution breakpoint is fault-like and would fire
            // again immediately, so disable its slot for that one step.
            if ((bp.access & (BP_ACC_READ | BP_ACC_WRITE)) == 0 && bp.slot >= 0) {
                CpuState st;
                if (get_state(st, e)) {
                    st.dr7 &= ~(1ULL << (bp.slot * 2));  // clear local enable
                    if (set_state(st, e)) hw_silent_slot_ = bp.slot;
                }
            }
            silent_step_ = true;
            set_trap_flag(true, e);
            stop = false;
            return true;
        }
        // An execution breakpoint is fault-like: RIP still points at the
        // instruction, so resuming would fire it again. Remember the slot so
        // the next resume can step over it with the slot temporarily off.
        at_hw_slot_ = ((bp.access & (BP_ACC_READ | BP_ACC_WRITE)) == 0 && bp.slot >= 0)
                          ? bp.slot
                          : -1;
        stop_ = StopInfo{StopReason::Breakpoint, fmt("hardware breakpoint %d hit", bp.id)};
        stop_.address = bp.address;
        stop_.bp_id = bp.id;
        stop = true;
        return true;
    }
    stop = false;
    return false;
}

bool Engine::handle_guard_breakpoint(uint64_t access_addr, uint32_t access_kind, bool& stop) {
    // The OS reports a guard exception for ANY access to a guarded page, and
    // our guard covers the whole page(s) the watched range lives in - not just
    // the watched bytes. Find the armed memory breakpoint whose guard region
    // contains the access first; only then decide whether this is a hit.
    Breakpoint* owner = nullptr;
    uint64_t watched = 0;
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Memory || !bp.enabled) continue;
        auto it = bp.plants.find(current_pid_);
        if (it == bp.plants.end() || !it->second.planted) continue;
        const BpPlant& pl = it->second;
        uint64_t lo = pl.region_base, hi = pl.region_base + pl.region_size;
        if (access_addr < lo || access_addr >= hi) continue;
        owner = &bp;
        watched = pl.address ? pl.address : bp.address;
        break;
    }
    if (!owner) return false;  // the target's own guard page

    bool in_range = access_addr >= watched && access_addr < watched + owner->size;
    // ExceptionInformation[0]: 0 = read, 1 = write, 8 = execute
    bool kind_ok = (access_kind == 1 && (owner->access & BP_ACC_WRITE)) ||
                   (access_kind == 0 && (owner->access & BP_ACC_READ)) ||
                   (access_kind == 8 && (owner->access & BP_ACC_EXEC));

    std::string e;
    if (in_range && kind_ok) {
        bool should_stop = true;
        if (!owner->command.empty() && command_hook_) {
            in_hit_command_ = true;
            command_hook_(owner->command);
            in_hit_command_ = false;
        }
        evaluate_condition(*owner, should_stop, e);
        owner->hit_count++;
        guard_rearm_id_ = owner->id;  // re-arm after stepping past
        if (!should_stop) {
            silent_step_ = true;
            set_trap_flag(true, e);
            stop = false;
            return true;
        }
        stop_ = StopInfo{StopReason::GuardBreak, fmt("memory breakpoint %d hit at %s", owner->id,
                                                     hex8(access_addr).c_str())};
        stop_.address = access_addr;
        stop_.bp_id = owner->id;
        stop = true;
        return true;
    }

    // An access to the guarded page(s) outside the watched bytes, or of an
    // access type the user did not ask to watch. The OS already consumed the
    // guard bit, so let the instruction re-run (DBG_CONTINUE) and step it
    // silently; the SINGLE_STEP handler re-arms the guard afterwards. Handing
    // the exception to the target instead kills it - normal programs do not
    // handle guard violations.
    guard_rearm_id_ = owner->id;
    silent_step_ = true;
    set_trap_flag(true, e);
    stop = false;
    return true;
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
    if (bp && bp->enabled) {
        // replant at the address this process actually uses: a symbol
        // breakpoint can live at a different base in each process
        BpPlant& pl = bp->plant_of(current_pid_);
        bps.plant_software(process(), current_pid_, *bp, e,
                           pl.address ? pl.address : bp->address);
    }
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
    capture_clean(st, "", e);
}

bool Engine::snapshot_save(const std::string& name, std::string& err) {
    if (!is_paused()) {
        err = "target is not paused";
        return false;
    }
    CpuState st;
    if (!get_state(st, err)) return false;
    return capture_clean(st, name, err);
}

void Engine::lift_int3(uint32_t pid) {
    // A breakpoint parked on (at_bp_id_) is already lifted - plants say so -
    // and stays lifted, so the read sees the real byte there too.
    ProcessInfo* p = proc_by_pid(pid);
    if (!p) return;
    std::string e2;
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Software) continue;
        auto it = bp.plants.find(pid);
        if (it == bp.plants.end() || !it->second.planted) continue;
        bps.unplant_software(p->handle, pid, bp, e2);
        lifted_.push_back(bp.id);
    }
    hide.lift_for_capture(pid);
}

void Engine::replant_int3(uint32_t pid) {
    ProcessInfo* p = proc_by_pid(pid);
    if (!p) {
        lifted_.clear();
        return;
    }
    std::string e2;
    for (int id : lifted_) {
        if (Breakpoint* bp = bps.find(id)) {
            auto it = bp->plants.find(pid);
            uint64_t a = (it != bp->plants.end() && it->second.address) ? it->second.address
                                                                        : bp->address;
            bps.plant_software(p->handle, pid, *bp, e2, a);
        }
    }
    lifted_.clear();
    hide.replant_after_capture(pid);
}

bool Engine::capture_clean(const CpuState& st, const std::string& name, std::string& err) {
    const uint32_t pid = current_pid_;
    lift_int3(pid);
    bool ok = snaps.capture(process(), is32(), pid, st, stop_.text, name, err);
    replant_int3(pid);
    return ok;
}

void Engine::finish_snapshot_restore(uint32_t rpid) {
    // Put every kind of breakpoint back: software and guard pages in this
    // process, hardware registers in all threads.
    std::string e;
    bool hardware_done = false;
    const ProcessInfo* rp = cur_proc();
    for (auto& bp : bps.all()) {
        if (!bp.enabled) continue;
        if (bp.kind == BpKind::Software)
            bps.plant_software(process(), rpid, bp, e,
                               rp ? bp_address_for(bp, *rp) : bp.address);
        else if (bp.kind == BpKind::Memory)
            arm_guard(bp, rpid, e, rp ? bp_address_for(bp, *rp) : bp.address);
        else if (bp.kind == BpKind::Hardware && !hardware_done) {
            plant_all_hardware(e);
            hardware_done = true;
        }
    }

    // the restored RIP may sit exactly on a breakpoint: park on it like a hit
    at_bp_id_ = 0;
    replant_pending_ = 0;
    guard_rearm_id_ = 0;
    silent_step_ = false;
    hw_silent_slot_ = -1;
    at_hw_slot_ = -1;
    CpuState st;
    if (get_state(st, e)) {
        Breakpoint* bp = bps.at_address_for_pid(st.rip, rpid);
        if (bp) {
            bps.unplant_software(process(), rpid, *bp, e);
            at_bp_id_ = bp->id;
        }
    }
    stop_ = StopInfo{StopReason::Step, "restored from snapshot"};
}

bool Engine::snapshot_restore(const std::string& name, std::string& err) {
    if (!is_paused()) {
        err = "target is not paused";
        return false;
    }
    // Take the INT3s of the restored process out first: the snapshot holds
    // real instruction bytes and restoring on top of our patches would corrupt
    // the code. Other processes are untouched by this restore.
    const uint32_t rpid = current_pid_;
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Software) continue;
        auto it = bp.plants.find(rpid);
        if (it != bp.plants.end() && it->second.planted)
            bps.unplant_software(process(), rpid, bp, err);
    }

    if (!snaps.restore_by_name(process(), thread_handle_, name, err)) return false;

    finish_snapshot_restore(rpid);
    return true;
}

bool Engine::snapshot_restore_from_store(uint32_t id, std::string& err) {
    if (!is_paused()) {
        err = "target is not paused";
        return false;
    }
    // same discipline as snapshot_restore: lift the INT3s first, restore the
    // pages, then re-arm everything (the old `snapshot load` path restored
    // straight over planted breakpoints and left their bookkeeping stale)
    const uint32_t rpid = current_pid_;
    for (auto& bp : bps.all()) {
        if (bp.kind != BpKind::Software) continue;
        auto it = bp.plants.find(rpid);
        if (it != bp.plants.end() && it->second.planted)
            bps.unplant_software(process(), rpid, bp, err);
    }

    if (!snaps.restore_from_store(id, process(), thread_handle_, err)) return false;

    finish_snapshot_restore(rpid);
    return true;
}

bool Engine::resume_inner(ResumeAction act, uint64_t until_addr, uint32_t timeout_ms,
                          std::string& err) {
    if (in_hit_command_) {
        // resuming from inside a breakpoint on-hit command would re-enter the
        // debug event pump while its event is still being processed
        err = "execution control is not allowed from a breakpoint on-hit command";
        return false;
    }
    if (!active()) {
        // the handle lingers after EXIT_PROCESS, so check liveness explicitly:
        // stepping a dead debuggee would wait forever for an event that never
        // arrives
        err = "the target has exited";
        return false;
    }
    if (!has_pending_) {
        // A previous `continue <timeout>` timed out: the target is still
        // running. Continuing again is just another wait; stepping needs a
        // stop first (`pause`).
        if (act == ResumeAction::Continue) return wait_for_stop(timeout_ms, err);
        err = "target is running; use 'pause' first";
        return false;
    }

    bool at_sw_bp = at_bp_id_ != 0;
    bool at_guard = guard_rearm_id_ != 0;

    // An execution hardware breakpoint is fault-like: RIP still points at the
    // instruction, so a plain continue would fire it again forever. Step over
    // it once with its DR7 slot disabled. `silent` swallows that single step
    // (continue / temp-bp paths); otherwise it becomes the user's step.
    auto prep_hw = [&](bool silent) -> bool {
        if (at_hw_slot_ < 0) return true;
        CpuState st;
        if (!get_state(st, err)) return false;
        st.dr7 &= ~(1ULL << (at_hw_slot_ * 2));  // clear local enable
        st.rflags |= 0x100;                     // TF
        if (!set_state(st, err)) return false;
        hw_silent_slot_ = at_hw_slot_;
        at_hw_slot_ = -1;
        if (silent) silent_step_ = true;
        return true;
    };

    switch (act) {
        case ResumeAction::StepInto: {
            if (!prep_hw(false)) return false;
            if (at_sw_bp || at_guard) return single_step_replant(err);
            return single_step(err);
        }
        case ResumeAction::Continue: {
            if (!prep_hw(true)) return false;
            if (at_sw_bp || at_guard) {
                if (!single_step_replant(err)) return false;
                // the replant step can itself stop on something (a breakpoint
                // at the callee's first instruction, a fault); surface that
                // instead of running on and swallowing it
                if (stop_.reason != StopReason::Step) return true;
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
                if (!prep_hw(true)) return false;
                if (at_sw_bp || at_guard) {
                    if (!single_step_replant(err)) return false;
                    // the internal step can itself stop on something (a
                    // breakpoint at the callee's first instruction, an
                    // exception on the stepped instruction); surface that
                    // instead of running on and swallowing it
                    if (stop_.reason != StopReason::Step) return true;
                }
                return resume_wait(timeout_ms, err);
            }
            if (!prep_hw(false)) return false;
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
            if (!prep_hw(true)) return false;
            if (at_sw_bp || at_guard) {
                if (!single_step_replant(err)) return false;
                if (stop_.reason != StopReason::Step) return true;
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
            if (!prep_hw(true)) return false;
            if (at_sw_bp || at_guard) {
                if (!single_step_replant(err)) return false;
                if (stop_.reason != StopReason::Step) return true;
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

bool Engine::pause(uint32_t timeout_ms, std::string& err) {
    if (!active()) {
        err = "no active target";
        return false;
    }
    if (has_pending_) return true;  // already stopped on a pending event

    // DebugBreakProcess's remote thread (DbgUiRemoteBreakin) checks
    // PEB.BeingDebugged: when the hider has cleared it, the thread takes the
    // "not debugged" path and exits without raising INT3, so the pause hangs.
    // Set the flag for the duration of the injection and put it back after.
    PebInfo peb;
    std::string pe;
    const bool flip_being_debugged = hide.enabled() && hide.config().peb_being_debugged &&
                                     read_peb(process(), is32(), peb, pe);
    const uint8_t one = 1, zero = 0;
    if (flip_being_debugged)
        write_memory(process(), peb.address + 0x2, &one, 1, pe);

    // Claim the next breakpoint from this process as ours: DbgBreakProcess
    // raises it at ntdll!DbgBreakPoint, which the child-startup-break filter
    // below would otherwise swallow when the current process is a child.
    expecting_break_pid_ = current_pid_;
    bool ok = interrupt(err);
    if (ok) ok = wait_for_stop(timeout_ms ? timeout_ms : 5000, err);
    if (!ok) expecting_break_pid_ = 0;

    if (flip_being_debugged)
        write_memory(process(), peb.address + 0x2, &zero, 1, pe);
    return ok;
}

// ---------------------------------------------------------------- breakpoints

bool Engine::arm_guard(Breakpoint& bp, uint32_t pid, std::string& err, uint64_t addr) {
    ProcessInfo* p = proc_by_pid(pid);
    if (!p) {
        err = "no such process";
        return false;
    }
    if (!addr) addr = bp.address;
    MemRegion reg;
    if (!region_at(p->handle, addr, reg)) {
        err = "cannot query region for memory breakpoint";
        return false;
    }
    // Guard granularity is the page and a guard exception costs a full debug
    // round trip, so guard only the pages the watched range actually covers -
    // not every page of the region around it. Never cross the region end.
    const uint64_t page = 0x1000;
    uint64_t lo = addr & ~(page - 1);
    uint64_t hi = ((addr + bp.size + page - 1) & ~(page - 1));
    uint64_t reg_end = reg.base + reg.size;
    if (hi > reg_end) hi = reg_end;
    if (hi <= lo) {
        err = "invalid memory breakpoint range";
        return false;
    }
    // strip a pre-existing guard bit (ours, from a double arm or a second
    // breakpoint on the same page) so the stored protection is the page's
    // real one and disarm truly removes the guard
    const DWORD prot = reg.protect & ~PAGE_GUARD;
    DWORD old = 0;
    if (!protect_memory(p->handle, lo, (size_t)(hi - lo), prot | PAGE_GUARD, old, err))
        return false;
    BpPlant& pl = bp.plant_of(pid);
    pl.address = addr;
    pl.region_base = lo;
    pl.region_size = (size_t)(hi - lo);
    pl.region_protect = prot;
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
        if (!p.alive || p.is_system) continue;
        for (auto& t : p.threads) {
            if (!t.handle || !t.alive) continue;
            CpuState st;
            if (!aj::get_state(t.handle, p.is32, st, err)) continue;
            st.dr[0] = st.dr[1] = st.dr[2] = st.dr[3] = 0;
            st.dr7 = 0;
            for (size_t i = 0; i < hw.size() && i < 4; ++i) {
                Breakpoint* bp = hw[i];
                bp->slot = (int)i;
                st.dr[i] = bp_address_for(*bp, p);
                unsigned rw, len;
                // Intel: 00 = execute, 01 = write, 11 = read/write. A
                // read-only watch (10) does not exist on x86/x64, so READ maps
                // to read/write. "rw" must map to 3, not to the write-only 1.
                if ((bp->access & BP_ACC_WRITE) && (bp->access & BP_ACC_READ)) {
                    rw = 3;
                } else if (bp->access & BP_ACC_WRITE) {
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
                if (!p.alive || p.is_system) continue;
                std::string e;
                if (bps.plant_software(p.handle, p.pid, bp, e, bp_address_for(bp, p))) {
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
                if (!p.alive || p.is_system) continue;
                std::string e;
                if (arm_guard(bp, p.pid, e, bp_address_for(bp, p))) {
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
                if (!p.alive || p.is_system) continue;
                if (enabled)
                    bps.plant_software(p.handle, p.pid, *bp, err, bp_address_for(*bp, p));
                else
                    bps.unplant_software(p.handle, p.pid, *bp, err);
            }
            return true;
        case BpKind::Hardware:
            return plant_all_hardware(err);
        case BpKind::Memory:
            for (auto& p : processes_) {
                if (!p.alive || p.is_system) continue;
                if (enabled)
                    arm_guard(*bp, p.pid, err, bp_address_for(*bp, p));
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
            if (!p.alive || p.is_system) continue;
            if (bp.kind == BpKind::Software)
                bps.plant_software(p.handle, p.pid, bp, e, bp_address_for(bp, p));
            else if (bp.kind == BpKind::Memory)
                arm_guard(bp, p.pid, e, bp_address_for(bp, p));
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
