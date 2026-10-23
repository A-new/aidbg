#include "engine/memory.h"

#include <windows.h>

#include <cstring>

#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

bool read_memory(HANDLE proc, uint64_t addr, void* buf, size_t n, std::string& err,
                 size_t* got) {
    SIZE_T done = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)addr, buf, n, &done)) {
        DWORD e = GetLastError();
        if (done == 0) {
            err = fmt("ReadProcessMemory(%s) failed: %s", hex8(addr).c_str(),
                      last_error_text(e).c_str());
            return false;
        }
    }
    if (got) *got = (size_t)done;
    return done > 0;
}

bool read_memory_exact(HANDLE proc, uint64_t addr, void* buf, size_t n, std::string& err) {
    size_t got = 0;
    if (!read_memory(proc, addr, buf, n, err, &got)) return false;
    if (got != n) {
        err = fmt("ReadProcessMemory(%s) returned only %zu of %zu bytes", hex8(addr).c_str(), got,
                  n);
        return false;
    }
    return true;
}

bool write_memory(HANDLE proc, uint64_t addr, const void* buf, size_t n, std::string& err) {
    SIZE_T done = 0;
    DWORD old = 0;
    // temporarily widen protection so patched .text pages can be written
    VirtualProtectEx(proc, (LPVOID)(uintptr_t)addr, n, PAGE_EXECUTE_READWRITE, &old);
    BOOL ok = WriteProcessMemory(proc, (LPVOID)(uintptr_t)addr, buf, n, &done);
    DWORD e = GetLastError();
    if (old) VirtualProtectEx(proc, (LPVOID)(uintptr_t)addr, n, old, &old);
    if (!ok || done != n) {
        err = fmt("WriteProcessMemory(%s) failed: %s", hex8(addr).c_str(),
                  last_error_text(e).c_str());
        return false;
    }
    return true;
}

bool read_u64(HANDLE proc, uint64_t addr, uint64_t& out, std::string& err) {
    size_t got = 0;
    if (!read_memory(proc, addr, &out, sizeof(out), err, &got) || got != sizeof(out))
        return false;
    return true;
}

bool flush_icache(HANDLE proc, uint64_t addr, size_t n) {
    return FlushInstructionCache(proc, (LPCVOID)(uintptr_t)addr, n) != 0;
}

bool alloc_memory(HANDLE proc, size_t n, uint64_t& out, std::string& err, uint64_t hint) {
    // With a hint the block lands near that address, which matters for
    // RIP-relative references: their displacement is only 32 bits wide.
    LPVOID p = VirtualAllocEx(proc, hint ? (LPVOID)(uintptr_t)hint : nullptr, n,
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) {
        err = fmt("VirtualAllocEx failed: %s", last_error_text().c_str());
        return false;
    }
    out = (uint64_t)(uintptr_t)p;
    return true;
}

bool alloc_memory_near(HANDLE proc, size_t n, uint64_t hint, uint64_t& out, std::string& err) {
    // RIP-relative displacements only reach +/-2GB, so the block has to land
    // close to the code that will reference it. Walk outward from the hint
    // looking for free address space instead of letting the allocator pick
    // something far away.
    const uint64_t kHalf = 0x70000000ULL;  // stay comfortably inside int32
    uint64_t lo = hint > kHalf ? hint - kHalf : 0x10000;
    uint64_t hi = hint + kHalf;

    for (int pass = 0; pass < 2; ++pass) {
        uint64_t a = pass == 0 ? ((hint + 0xFFFF) & ~0xFFFFULL)
                               : (((hint - 0x10000) & ~0xFFFFULL));
        while (a >= lo && a < hi) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)a, &mbi, sizeof(mbi))) break;
            uint64_t base = (uint64_t)(uintptr_t)mbi.BaseAddress;
            uint64_t next = base + mbi.RegionSize;
            if (mbi.State == MEM_FREE && mbi.RegionSize >= n) {
                LPVOID p = VirtualAllocEx(proc, (LPVOID)(uintptr_t)a, n,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) {
                    out = (uint64_t)(uintptr_t)p;
                    return true;
                }
            }
            if (pass == 0) {
                if (next <= a) break;
                a = next;
            } else {
                if (base <= lo) break;
                a = base - 1;
            }
        }
    }
    err = fmt("no free memory within 2GB of %s", hex8(hint).c_str());
    return false;
}

bool free_memory(HANDLE proc, uint64_t addr, std::string& err) {
    if (!VirtualFreeEx(proc, (LPVOID)(uintptr_t)addr, 0, MEM_RELEASE)) {
        err = fmt("VirtualFreeEx failed: %s", last_error_text().c_str());
        return false;
    }
    return true;
}

bool protect_memory(HANDLE proc, uint64_t addr, size_t n, DWORD prot, DWORD& old_prot,
                    std::string& err) {
    if (!VirtualProtectEx(proc, (LPVOID)(uintptr_t)addr, n, prot, &old_prot)) {
        err = fmt("VirtualProtectEx failed: %s", last_error_text().c_str());
        return false;
    }
    return true;
}

std::vector<MemRegion> query_regions(HANDLE proc, uint64_t start, uint64_t end) {
    std::vector<MemRegion> out;
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = start;
    while (addr < (end ? end : (uint64_t)-1)) {
        SIZE_T r = VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
        if (r == 0) break;
        MemRegion mr;
        mr.base = (uint64_t)(uintptr_t)mbi.BaseAddress;
        mr.size = (size_t)mbi.RegionSize;
        mr.protect = mbi.Protect;
        mr.state = mbi.State;
        mr.type = mbi.Type;
        out.push_back(mr);
        uint64_t next = mr.base + mr.size;
        if (next <= addr) break;
        addr = next;
        if (end && addr >= end) break;
    }
    return out;
}

bool region_at(HANDLE proc, uint64_t addr, MemRegion& out) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) return false;
    out.base = (uint64_t)(uintptr_t)mbi.BaseAddress;
    out.size = (size_t)mbi.RegionSize;
    out.protect = mbi.Protect;
    out.state = mbi.State;
    out.type = mbi.Type;
    return true;
}

bool search_memory(HANDLE proc, uint64_t start, uint64_t end, const std::vector<uint8_t>& bytes,
                   const std::vector<bool>& mask, size_t max_hits, std::vector<uint64_t>& hits,
                   std::string& err) {
    if (bytes.empty()) {
        err = "empty pattern";
        return false;
    }
    if (end <= start) {
        err = "invalid range";
        return false;
    }
    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK + bytes.size());
    uint64_t addr = start;
    while (addr < end && hits.size() < max_hits) {
        MemRegion reg;
        if (!region_at(proc, addr, reg) || reg.size == 0) break;
        uint64_t reg_end = reg.base + reg.size;
        bool readable = (reg.state == MEM_COMMIT) &&
                        !(reg.protect & (PAGE_NOACCESS | PAGE_GUARD));
        if (!readable) {
            addr = reg_end;
            continue;
        }
        uint64_t seg_end = reg_end < end ? reg_end : end;
        for (uint64_t p = addr; p < seg_end && hits.size() < max_hits;) {
            size_t want = (size_t)(seg_end - p);
            if (want > CHUNK) want = CHUNK;
            size_t got = 0;
            std::string e2;
            if (!read_memory(proc, p, buf.data(), want, e2, &got) || got == 0) break;
            for (size_t i = 0; i + bytes.size() <= got; ++i) {
                bool match = true;
                for (size_t k = 0; k < bytes.size(); ++k) {
                    if (mask[k] && buf[i + k] != bytes[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    hits.push_back(p + i);
                    if (hits.size() >= max_hits) break;
                }
            }
            // overlap so patterns straddling chunk borders are found
            size_t step = got > bytes.size() ? got - bytes.size() + 1 : 1;
            p += step;
            if (got < want) break;
        }
        addr = seg_end;
    }
    return true;
}

std::string protect_text(DWORD p) {
    if (p & PAGE_GUARD) return "GUARD";
    bool x = (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                   PAGE_EXECUTE_WRITECOPY)) != 0;
    bool r = (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    bool w = (p & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                   PAGE_EXECUTE_WRITECOPY)) != 0;
    if (p & PAGE_NOACCESS) return "---";
    std::string s;
    s += r ? 'r' : '-';
    s += w ? 'w' : '-';
    s += x ? 'x' : '-';
    return s;
}

std::string state_text(DWORD s) {
    switch (s) {
        case MEM_COMMIT: return "commit";
        case MEM_FREE: return "free";
        case MEM_RESERVE: return "reserve";
    }
    return "?";
}

Json region_json(const MemRegion& r) {
    Json j = Json::obj();
    j.set_hex("base", r.base);
    j.set_u("size", (uint64_t)r.size);
    j.set_str("protect", protect_text(r.protect));
    j.set_u("protect_raw", r.protect);
    j.set_str("state", state_text(r.state));
    if (!r.module.empty()) j.set_str("module", r.module);
    return j;
}

std::string hexdump(HANDLE proc, uint64_t addr, size_t n, std::string& err) {
    std::vector<uint8_t> buf(n);
    size_t got = 0;
    if (!read_memory(proc, addr, buf.data(), n, err, &got) || got == 0) return {};
    std::string out;
    for (size_t i = 0; i < got; i += 16) {
        out += fmt("%s  ", hex8(addr + i).c_str());
        std::string ascii;
        for (size_t k = 0; k < 16; ++k) {
            if (i + k < got) {
                out += fmt("%02X ", buf[i + k]);
                uint8_t c = buf[i + k];
                ascii += (c >= 0x20 && c < 0x7f) ? (char)c : '.';
            } else {
                out += "   ";
                ascii += ' ';
            }
        }
        out += " |" + ascii + "|\n";
    }
    return out;
}

}  // namespace aj
