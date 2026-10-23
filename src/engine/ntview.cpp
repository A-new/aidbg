#include "engine/ntview.h"

#include <tlhelp32.h>

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include "engine/memory.h"
#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

namespace {

// ntdll exports we resolve at runtime; no import library needed
using NtQueryInformationProcess_t = LONG(__stdcall*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThread_t = LONG(__stdcall*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQuerySystemInformation_t = LONG(__stdcall*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObject_t = LONG(__stdcall*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQueryInformationProcess_t pNtQueryInformationProcess = nullptr;
NtQueryInformationThread_t pNtQueryInformationThread = nullptr;
NtQuerySystemInformation_t pNtQuerySystemInformation = nullptr;
NtQueryObject_t pNtQueryObject = nullptr;
bool resolved = false;

void resolve_ntdll() {
    if (resolved) return;
    resolved = true;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    pNtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtQueryInformationThread =
        (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
    pNtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQueryObject = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");
}

constexpr ULONG kProcessBasicInformation = 0;
constexpr ULONG kProcessWow64Information = 26;
constexpr ULONG kThreadBasicInformation = 0;
constexpr ULONG kObjectTypeInformation = 2;
constexpr ULONG kSystemExtendedHandleInformation = 64;

// field offsets inside the target's TEB / PEB; stable across recent versions
struct Layout {
    uint32_t teb_stack_base, teb_stack_limit, teb_client_id, teb_peb, teb_last_error,
        teb_dealloc_stack;
    uint32_t peb_being_debugged, peb_image_base, peb_ldr, peb_params, peb_heap,
        peb_ntglobalflag, peb_num_procs, peb_session;
    uint32_t peb_num_heaps, peb_heaps;
    uint32_t ptr;  // pointer size
};

const Layout& layout(bool is32) {
    static const Layout l64 = {
        0x08, 0x10, 0x40, 0x60, 0x68, 0x1478,
        0x002, 0x010, 0x018, 0x020, 0x030, 0x0BC, 0x0B8, 0x2C0,
        0x0E8, 0x0F0,
        8,
    };
    static const Layout l32 = {
        0x04, 0x08, 0x20, 0x30, 0x34, 0x0E0C,
        0x002, 0x008, 0x00C, 0x010, 0x018, 0x068, 0x064, 0x1D4,
        0x088, 0x090,
        4,
    };
    return is32 ? l32 : l64;
}

bool rd(HANDLE proc, uint64_t addr, void* buf, size_t n) {
    std::string e;
    size_t got = 0;
    return read_memory(proc, addr, buf, n, e, &got) && got == n;
}

uint64_t rd_ptr(HANDLE proc, uint64_t addr, size_t ps) {
    uint64_t v = 0;
    if (ps == 4) {
        uint32_t x = 0;
        if (!rd(proc, addr, &x, 4)) return 0;
        v = x;
    } else {
        if (!rd(proc, addr, &v, 8)) return 0;
    }
    return v;
}

uint32_t rd_u32(HANDLE proc, uint64_t addr) {
    uint32_t v = 0;
    rd(proc, addr, &v, 4);
    return v;
}

uint8_t rd_u8(HANDLE proc, uint64_t addr) {
    uint8_t v = 0;
    rd(proc, addr, &v, 1);
    return v;
}

}  // namespace

// -------------------------------------------------------------------- TEB

bool read_teb(HANDLE proc, HANDLE thread, bool is32, TebInfo& out, std::string& err,
              uint64_t expected_peb) {
    resolve_ntdll();
    out = TebInfo();
    out.is32 = is32;
    if (!pNtQueryInformationThread) {
        err = "NtQueryInformationThread is not available";
        return false;
    }

    // THREAD_BASIC_INFORMATION and PROCESS_BASIC_INFORMATION both reject any
    // length other than their exact struct size with STATUS_INFO_LENGTH_MISMATCH
    // (48 bytes on x64 - passing a bigger buffer does NOT work).
    uint8_t buf[48] = {0};
    LONG st = pNtQueryInformationThread(thread, kThreadBasicInformation, buf, sizeof(buf), nullptr);
    if (st != 0) {
        err = fmt("NtQueryInformationThread failed: 0x%08lX", (unsigned long)st);
        return false;
    }
    uint64_t teb = is32 ? (uint64_t)*(uint32_t*)(buf + 8) : *(uint64_t*)(buf + 8);
    if (!teb) {
        err = "no TEB for this thread";
        return false;
    }

    // For a WOW64 thread the address returned is the 64-bit TEB while the
    // fields we want live in the 32-bit layout (or vice versa). Fill with the
    // assumed layout and fall back to the other one if the ClientId does not
    // match this process - that is a reliable self-check.
    DWORD want_pid = GetProcessId(proc);
    auto fill = [&](bool layout32, TebInfo& t) {
        const Layout& L = layout(layout32);
        t = TebInfo();
        t.is32 = layout32;
        t.address = teb;
        t.pid = rd_ptr(proc, teb + L.teb_client_id, L.ptr);
        t.tid = rd_ptr(proc, teb + L.teb_client_id + L.ptr, L.ptr);
        t.peb = rd_ptr(proc, teb + L.teb_peb, L.ptr);
        t.stack_base = rd_ptr(proc, teb + L.teb_stack_base, L.ptr);
        t.stack_limit = rd_ptr(proc, teb + L.teb_stack_limit, L.ptr);
        t.last_error = rd_u32(proc, teb + L.teb_last_error);
        t.deallocation_stack = rd_ptr(proc, teb + L.teb_dealloc_stack, L.ptr);
    };

    fill(is32, out);
    if (expected_peb && out.peb != expected_peb) {
        // WOW64 threads have two TEBs; prefer whichever one points at the PEB
        // that read_peb already validated
        TebInfo alt;
        fill(!is32, alt);
        if (alt.peb == expected_peb || out.pid != (uint64_t)want_pid) out = alt;
    } else if (out.pid != (uint64_t)want_pid) {
        TebInfo alt;
        fill(!is32, alt);
        if (alt.pid == (uint64_t)want_pid) out = alt;
    }
    return true;
}

// -------------------------------------------------------------------- PEB

bool read_peb(HANDLE proc, bool is32, PebInfo& out, std::string& err) {
    resolve_ntdll();
    out = PebInfo();
    out.is32 = is32;
    if (!pNtQueryInformationProcess) {
        err = "NtQueryInformationProcess is not available";
        return false;
    }

    uint64_t peb = 0;
    if (is32) {
        // A WOW64 process has both a 32-bit and a 64-bit PEB; ProcessBasicInformation
        // hands back the 64-bit one, which has a different layout. The 32-bit PEB
        // comes from ProcessWow64Information.
        uint8_t w[8] = {0};
        LONG s = pNtQueryInformationProcess(proc, kProcessWow64Information, w, sizeof(w),
                                            nullptr);
        if (s != 0) {
            err = fmt("NtQueryInformationProcess(ProcessWow64Information) failed: 0x%08lX",
                      (unsigned long)s);
            return false;
        }
        peb = (uint64_t)*(uint32_t*)w;
    } else {
        // PROCESS_BASIC_INFORMATION: exact size only (48 on x64)
        uint8_t buf[48] = {0};
        LONG st =
            pNtQueryInformationProcess(proc, kProcessBasicInformation, buf, sizeof(buf), nullptr);
        if (st != 0) {
            err = fmt("NtQueryInformationProcess failed: 0x%08lX", (unsigned long)st);
            return false;
        }
        peb = *(uint64_t*)(buf + 8);
    }
    if (!peb) {
        err = "no PEB for this process";
        return false;
    }
    const Layout& L = layout(is32);
    out.address = peb;
    out.being_debugged = rd_u8(proc, peb + L.peb_being_debugged);
    out.image_base = rd_ptr(proc, peb + L.peb_image_base, L.ptr);
    out.ldr = rd_ptr(proc, peb + L.peb_ldr, L.ptr);
    out.process_parameters = rd_ptr(proc, peb + L.peb_params, L.ptr);
    out.process_heap = rd_ptr(proc, peb + L.peb_heap, L.ptr);
    out.nt_global_flag = rd_u32(proc, peb + L.peb_ntglobalflag);
    out.number_of_processors = rd_u32(proc, peb + L.peb_num_procs);
    out.session_id = rd_u32(proc, peb + L.peb_session);
    return true;
}

// ------------------------------------------------------------------- heaps

// Heaps are taken from the PEB's ProcessHeaps array. Toolhelp's heap snapshot
// (TH32CS_SNAPHEAPLIST) fails with ERROR_CRC on a process stopped by a
// debugger, so reading the PEB is both more reliable and version-stable.
bool enum_heaps(uint32_t pid, std::vector<HeapInfo>& out, size_t max_blocks_per_heap,
                std::string& err) {
    out.clear();
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) {
        err = fmt("cannot open process %u: %s", pid, last_error_text().c_str());
        return false;
    }

    PebInfo peb;
    if (!read_peb(proc, false, peb, err)) {
        // try the 32-bit layout before giving up
        std::string e2;
        if (!read_peb(proc, true, peb, err)) {
            CloseHandle(proc);
            return false;
        }
    }

    const Layout& L = layout(peb.is32);
    uint32_t nheaps = rd_u32(proc, peb.address + L.peb_num_heaps);
    uint64_t heaps_ptr = rd_ptr(proc, peb.address + L.peb_heaps, L.ptr);
    if (!heaps_ptr || nheaps == 0 || nheaps > 4096) {
        CloseHandle(proc);
        err = "cannot locate the heap array in the PEB";
        return false;
    }

    if (!max_blocks_per_heap) max_blocks_per_heap = 200;
    for (uint32_t i = 0; i < nheaps; ++i) {
        uint64_t h = rd_ptr(proc, heaps_ptr + (uint64_t)i * L.ptr, L.ptr);
        if (!h) continue;
        HeapInfo info;
        info.id = h;
        // the region size is a good upper bound on the heap's committed span
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(proc, (LPCVOID)(uintptr_t)h, &mbi, sizeof(mbi)))
            info.total_bytes = mbi.RegionSize;
        out.push_back(std::move(info));
    }
    CloseHandle(proc);
    return true;
}

// ----------------------------------------------------------------- handles

namespace {
struct SysHandleEntry {
    void* object;
    ULONG_PTR pid;
    ULONG_PTR handle;
    ULONG access;
    USHORT creator;
    USHORT type_index;
    ULONG attributes;
    ULONG reserved;
};

std::string handle_type(HANDLE dup) {
    if (!pNtQueryObject) return {};
    std::vector<uint8_t> buf(2048);
    if (pNtQueryObject(dup, kObjectTypeInformation, buf.data(), (ULONG)buf.size(), nullptr) != 0)
        return {};
    USHORT len = *(USHORT*)buf.data();
    USHORT maxlen = *(USHORT*)(buf.data() + 2);
    wchar_t* p = *(wchar_t**)(buf.data() + 8);
    if (!p || !len || !maxlen) return {};
    // The kernel filled this buffer; the pointer must point inside it before
    // we dereference it on the debugger's thread.
    const uintptr_t lo = (uintptr_t)buf.data();
    const uintptr_t hi = lo + buf.size();
    const uintptr_t pv = (uintptr_t)p;
    if (pv < lo || pv > hi || len > buf.size() || (pv - lo) + len > buf.size()) return {};
    return to_utf8(std::wstring(p, len / sizeof(wchar_t)));
}

std::string handle_name(HANDLE dup) {
    if (!pNtQueryObject) return {};
    std::vector<uint8_t> buf(1024);
    if (pNtQueryObject(dup, 1 /*ObjectNameInformation*/, buf.data(), (ULONG)buf.size(),
                       nullptr) != 0)
        return {};
    USHORT len = *(USHORT*)buf.data();
    wchar_t* p = *(wchar_t**)(buf.data() + 8);
    if (!p || !len) return {};
    const uintptr_t lo = (uintptr_t)buf.data();
    const uintptr_t hi = lo + buf.size();
    const uintptr_t pv = (uintptr_t)p;
    if (pv < lo || pv > hi || len > buf.size() || (pv - lo) + len > buf.size()) return {};
    return to_utf8(std::wstring(p, len / sizeof(wchar_t)));
}
}  // namespace

bool enum_handles(uint32_t pid, const std::string& type_filter, std::vector<HandleInfo>& out,
                  size_t max, std::string& err) {
    out.clear();
    resolve_ntdll();
    if (!pNtQuerySystemInformation) {
        err = "NtQuerySystemInformation is not available";
        return false;
    }
    if (!max) max = 200;
    std::string want = to_lower(type_filter);

    // the system handle table is large (hundreds of thousands of entries), so
    // ask for the real size instead of guessing
    std::vector<uint8_t> buf(1 << 22);
    ULONG needed = 0;
    LONG st = 0;
    constexpr size_t kMaxHandleTable = 256u << 20;  // 256 MiB
    for (int attempt = 0; attempt < 8; ++attempt) {
        st = pNtQuerySystemInformation(kSystemExtendedHandleInformation, buf.data(),
                                       (ULONG)buf.size(), &needed);
        if (st == 0) break;
        if (st != (LONG)0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) break;
        if (needed > kMaxHandleTable) {
            err = "system handle table is unreasonably large";
            return false;
        }
        // Grow to the reported size plus slack instead of doubling without
        // bound; a broken/hostile reply must not drive a multi-GB allocation.
        size_t grow = needed ? (size_t)needed + 0x10000 : buf.size() * 2;
        if (grow > kMaxHandleTable) grow = kMaxHandleTable;
        if (grow <= buf.size()) break;
        buf.resize(grow);
    }
    if (st != 0) {
        err = fmt("NtQuerySystemInformation failed: 0x%08lX", (unsigned long)st);
        return false;
    }

    ULONG_PTR count = *(ULONG_PTR*)buf.data();
    const size_t entry_size = sizeof(SysHandleEntry);
    if (buf.size() < sizeof(ULONG_PTR) * 2 ||
        (size_t)count > (buf.size() - sizeof(ULONG_PTR) * 2) / entry_size) {
        err = "corrupt system handle table";
        return false;
    }

    // NtQueryObject(ObjectNameInformation) blocks forever when the handle is a
    // synchronous pipe mid-operation - the query waits for the other end. A
    // stuck call cannot be cancelled, so the per-handle loop runs on a worker
    // thread and we take whatever it gathered after a timeout; the worker (and
    // its buffer, moved into it) is simply abandoned if it never returns.
    struct EnumState {
        std::mutex mu;
        std::vector<HandleInfo> list;
        bool done = false;
    };
    auto shared = std::make_shared<EnumState>();
    std::thread worker([pid, want, max, count, entry_size, table = std::move(buf), shared] {
        const uint8_t* base = table.data() + sizeof(ULONG_PTR) * 2;
        // resolve the process once, not per handle
        HANDLE src = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!src) {
            std::lock_guard<std::mutex> lk(shared->mu);
            shared->done = true;
            return;
        }
        HANDLE self = GetCurrentProcess();
        // type names are expensive to query, cache them per type index
        std::map<USHORT, std::string> type_cache;
        std::vector<HandleInfo> local;

        for (ULONG_PTR i = 0; i < count && local.size() < max; ++i) {
            const SysHandleEntry* h = (const SysHandleEntry*)(base + i * entry_size);
            if ((uint32_t)h->pid != pid) continue;

            HandleInfo info;
            info.value = (uint64_t)h->handle;
            info.type_index = h->type_index;
            info.access = h->access;

            // only look inside the handle if we are actually going to report it
            HANDLE dup = nullptr;
            if (DuplicateHandle(src, (HANDLE)h->handle, self, &dup, 0, FALSE,
                                DUPLICATE_SAME_ACCESS)) {
                auto it = type_cache.find(h->type_index);
                if (it == type_cache.end()) {
                    std::string t = handle_type(dup);
                    it = type_cache.emplace(h->type_index, t).first;
                }
                info.type = it->second;
                if (!want.empty() && want != "*" &&
                    to_lower(info.type).find(want) == std::string::npos) {
                    CloseHandle(dup);
                    continue;  // filter before counting towards `max`
                }
                info.name = handle_name(dup);
                CloseHandle(dup);
            } else if (!want.empty() && want != "*") {
                continue;
            }
            local.push_back(std::move(info));
            // publish incrementally so a timeout still yields partial results
            if (local.size() % 16 == 0) {
                std::lock_guard<std::mutex> lk(shared->mu);
                shared->list = local;
            }
        }
        {
            std::lock_guard<std::mutex> lk(shared->mu);
            shared->list = std::move(local);
            shared->done = true;
        }
        CloseHandle(src);
    });

    constexpr DWORD kTimeoutMs = 3000;
    for (DWORD waited = 0;;) {
        {
            std::lock_guard<std::mutex> lk(shared->mu);
            if (shared->done) break;
        }
        if (waited >= kTimeoutMs) break;
        Sleep(25);
        waited += 25;
    }
    bool done = false;
    {
        std::lock_guard<std::mutex> lk(shared->mu);
        done = shared->done;
        out = std::move(shared->list);
    }
    if (done) {
        worker.join();
        return true;
    }
    // the worker is stuck in the kernel on some handle; keep what it published
    worker.detach();
    if (out.empty()) {
        err = fmt("handle enumeration timed out after %lu ms (a handle is stuck in the kernel, "
                  "typically a synchronous pipe)",
                  (unsigned long)kTimeoutMs);
        return false;
    }
    err = fmt("handle enumeration timed out after %lu ms; showing the first %zu entr%s",
              (unsigned long)kTimeoutMs, out.size(), out.size() == 1 ? "y" : "ies");
    return true;
}

// ---------------------------------------------------------------- reporting

Json teb_to_json(const TebInfo& t) {
    Json j = Json::obj();
    j.set_str("arch", t.is32 ? "x86" : "x64");
    j.set_hex("address", t.address);
    j.set_u("pid", t.pid);
    j.set_u("tid", t.tid);
    j.set_hex("peb", t.peb);
    j.set_hex("stack_base", t.stack_base);
    j.set_hex("stack_limit", t.stack_limit);
    j.set_u("stack_size", t.stack_base > t.stack_limit ? t.stack_base - t.stack_limit : 0);
    j.set_u("last_error", t.last_error);
    j.set_hex("deallocation_stack", t.deallocation_stack);
    return j;
}

Json peb_to_json(const PebInfo& p) {
    Json j = Json::obj();
    j.set_str("arch", p.is32 ? "x86" : "x64");
    j.set_hex("address", p.address);
    j.set_u("being_debugged", p.being_debugged);
    j.set_hex("image_base", p.image_base);
    j.set_hex("ldr", p.ldr);
    j.set_hex("process_parameters", p.process_parameters);
    j.set_hex("process_heap", p.process_heap);
    j.set_str("nt_global_flag", fmt("0x%X", p.nt_global_flag));
    j.set_u("number_of_processors", p.number_of_processors);
    j.set_u("session_id", p.session_id);
    return j;
}

}  // namespace aj
