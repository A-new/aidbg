#include "engine/registers.h"

#include <cstddef>
#include <cstring>

#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {
namespace {

// slot encoding
enum : int {
    S_GPR = 0,    // + 0..15
    S_RIP = 16,
    S_RFLAGS = 17,
    S_SEG = 18,   // + 0..5  (cs ds es fs gs ss)
    S_DR = 24,    // + 0..3
    S_DR6 = 28,
    S_DR7 = 29,
};

struct RegDef {
    const char* name;
    int slot;
    unsigned width;   // bytes
    unsigned shift;   // bits
    bool x64only;     // absent on x86 targets
};

#define G64(name, idx) {name, S_GPR + (idx), 8, 0, false}
#define X64(name, idx) {name, S_GPR + (idx), 8, 0, true}
#define G32(name, idx) {name, S_GPR + (idx), 4, 0, false}
#define X32(name, idx) {name, S_GPR + (idx), 4, 0, true}
#define G16(name, idx) {name, S_GPR + (idx), 2, 0, false}
#define G8L(name, idx) {name, S_GPR + (idx), 1, 0, false}
#define X8L(name, idx) {name, S_GPR + (idx), 1, 0, true}
#define G8H(name, idx) {name, S_GPR + (idx), 1, 8, false}

// x64only: false means "present on both architectures" (the 64-bit names of the
// low 8 general registers are aliases for the 32-bit ones on x86). Only the
// r8..r15 family truly does not exist on a 32-bit target.
const RegDef kRegs[] = {
    // 64-bit views (low 8 are portable, r8..r15 are x64 only)
    G64("rax", 0), G64("rcx", 1), G64("rdx", 2), G64("rbx", 3),
    G64("rsp", 4), G64("rbp", 5), G64("rsi", 6), G64("rdi", 7),
    X64("r8", 8), X64("r9", 9), X64("r10", 10), X64("r11", 11),
    X64("r12", 12), X64("r13", 13), X64("r14", 14), X64("r15", 15),
    {"rip", S_RIP, 8, 0, false},

    // 32-bit views
    G32("eax", 0), G32("ecx", 1), G32("edx", 2), G32("ebx", 3),
    G32("esp", 4), G32("ebp", 5), G32("esi", 6), G32("edi", 7),
    X32("r8d", 8), X32("r9d", 9), X32("r10d", 10), X32("r11d", 11),
    X32("r12d", 12), X32("r13d", 13), X32("r14d", 14), X32("r15d", 15),
    {"eip", S_RIP, 4, 0, false},

    // 16-bit views
    G16("ax", 0), G16("cx", 1), G16("dx", 2), G16("bx", 3),
    G16("sp", 4), G16("bp", 5), G16("si", 6), G16("di", 7),
    {"ip", S_RIP, 2, 0, false},

    // 8-bit views
    G8L("al", 0), G8L("cl", 1), G8L("dl", 2), G8L("bl", 3),
    G8L("spl", 4), G8L("bpl", 5), G8L("sil", 6), G8L("dil", 7),
    X8L("r8b", 8), X8L("r9b", 9), X8L("r10b", 10), X8L("r11b", 11),
    X8L("r12b", 12), X8L("r13b", 13), X8L("r14b", 14), X8L("r15b", 15),
    G8H("ah", 0), G8H("ch", 1), G8H("dh", 2), G8H("bh", 3),

    // flags
    {"rflags", S_RFLAGS, 8, 0, false},
    {"eflags", S_RFLAGS, 4, 0, false},
    {"flags", S_RFLAGS, 2, 0, false},

    // segments
    {"cs", S_SEG + 0, 2, 0, false}, {"ds", S_SEG + 1, 2, 0, false},
    {"es", S_SEG + 2, 2, 0, false}, {"fs", S_SEG + 3, 2, 0, false},
    {"gs", S_SEG + 4, 2, 0, false}, {"ss", S_SEG + 5, 2, 0, false},
};

#undef G64
#undef X64
#undef G32
#undef X32
#undef G16
#undef G8L
#undef X8L
#undef G8H

const RegDef* find_reg(const std::string& name, bool is32) {
    std::string n = name;
    for (auto& c : n) c = (char)tolower((unsigned char)c);
    if (!n.empty() && n[0] == '$') n = n.substr(1);
    for (const auto& r : kRegs) {
        if (n != r.name) continue;
        if (is32 && r.x64only) return nullptr;
        return &r;
    }
    return nullptr;
}

uint64_t raw_get(const CpuState& st, int slot) {
    switch (slot) {
        case S_RIP: return st.rip;
        case S_RFLAGS: return st.rflags;
        case S_DR6: return st.dr6;
        case S_DR7: return st.dr7;
        default: break;
    }
    if (slot >= S_SEG && slot < S_SEG + 6) return st.segs[slot - S_SEG];
    if (slot >= S_DR && slot < S_DR + 4) return st.dr[slot - S_DR];
    if (slot >= S_GPR && slot < S_GPR + 16) return st.gpr[slot - S_GPR];
    return 0;
}

void raw_set(CpuState& st, int slot, uint64_t v) {
    switch (slot) {
        case S_RIP: st.rip = v; return;
        case S_RFLAGS: st.rflags = v; return;
        case S_DR6: st.dr6 = v; return;
        case S_DR7: st.dr7 = v; return;
        default: break;
    }
    if (slot >= S_SEG && slot < S_SEG + 6) {
        st.segs[slot - S_SEG] = (uint16_t)v;
        return;
    }
    if (slot >= S_DR && slot < S_DR + 4) {
        st.dr[slot - S_DR] = v;
        return;
    }
    if (slot >= S_GPR && slot < S_GPR + 16) {
        st.gpr[slot - S_GPR] = v;
        return;
    }
}

uint64_t width_mask(unsigned width) {
    return width >= 8 ? ~(uint64_t)0 : (((uint64_t)1 << (width * 8)) - 1);
}

}  // namespace

bool get_state(HANDLE thread, bool is32, CpuState& out, std::string& err) {
    std::memset(&out, 0, sizeof(out));
    out.is32 = is32;

    if (is32) {
        WOW64_CONTEXT wc;
        std::memset(&wc, 0, sizeof(wc));
        wc.ContextFlags =
            WOW64_CONTEXT_FULL | WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_EXTENDED_REGISTERS;
        if (!Wow64GetThreadContext(thread, &wc)) {
            err = fmt("Wow64GetThreadContext failed: %s", last_error_text().c_str());
            return false;
        }
        out.gpr[0] = wc.Eax;
        out.gpr[1] = wc.Ecx;
        out.gpr[2] = wc.Edx;
        out.gpr[3] = wc.Ebx;
        out.gpr[4] = wc.Esp;
        out.gpr[5] = wc.Ebp;
        out.gpr[6] = wc.Esi;
        out.gpr[7] = wc.Edi;
        out.rip = wc.Eip;
        out.rflags = wc.EFlags;
        out.segs[0] = (uint16_t)wc.SegCs;
        out.segs[1] = (uint16_t)wc.SegDs;
        out.segs[2] = (uint16_t)wc.SegEs;
        out.segs[3] = (uint16_t)wc.SegFs;
        out.segs[4] = (uint16_t)wc.SegGs;
        out.segs[5] = (uint16_t)wc.SegSs;
        out.dr[0] = wc.Dr0;
        out.dr[1] = wc.Dr1;
        out.dr[2] = wc.Dr2;
        out.dr[3] = wc.Dr3;
        out.dr6 = wc.Dr6;
        out.dr7 = wc.Dr7;
        // ExtendedRegisters holds an FXSAVE image: MXCSR at +24, XMM0-7 at +160
        out.mxcsr = *(uint32_t*)(wc.ExtendedRegisters + 24);
        for (int i = 0; i < 8; ++i)
            std::memcpy(out.xmm[i], wc.ExtendedRegisters + 160 + i * 16, 16);
        return true;
    }

    CONTEXT c;
    std::memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) {
        err = fmt("GetThreadContext failed: %s", last_error_text().c_str());
        return false;
    }
    out.gpr[0] = c.Rax;
    out.gpr[1] = c.Rcx;
    out.gpr[2] = c.Rdx;
    out.gpr[3] = c.Rbx;
    out.gpr[4] = c.Rsp;
    out.gpr[5] = c.Rbp;
    out.gpr[6] = c.Rsi;
    out.gpr[7] = c.Rdi;
    out.gpr[8] = c.R8;
    out.gpr[9] = c.R9;
    out.gpr[10] = c.R10;
    out.gpr[11] = c.R11;
    out.gpr[12] = c.R12;
    out.gpr[13] = c.R13;
    out.gpr[14] = c.R14;
    out.gpr[15] = c.R15;
    out.rip = c.Rip;
    out.rflags = c.EFlags;
    out.segs[0] = c.SegCs;
    out.segs[1] = c.SegDs;
    out.segs[2] = c.SegEs;
    out.segs[3] = c.SegFs;
    out.segs[4] = c.SegGs;
    out.segs[5] = c.SegSs;
    out.dr[0] = c.Dr0;
    out.dr[1] = c.Dr1;
    out.dr[2] = c.Dr2;
    out.dr[3] = c.Dr3;
    out.dr6 = c.Dr6;
    out.dr7 = c.Dr7;
    out.mxcsr = c.FltSave.MxCsr;
    for (int i = 0; i < 16; ++i)
        std::memcpy(out.xmm[i], &c.FltSave.XmmRegisters[i], 16);
    return true;
}

bool set_state(HANDLE thread, const CpuState& st, std::string& err) {
    if (st.is32) {
        WOW64_CONTEXT wc;
        std::memset(&wc, 0, sizeof(wc));
        wc.ContextFlags =
            WOW64_CONTEXT_FULL | WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_EXTENDED_REGISTERS;
        if (!Wow64GetThreadContext(thread, &wc)) {
            err = fmt("Wow64GetThreadContext failed: %s", last_error_text().c_str());
            return false;
        }
        wc.Eax = (DWORD)st.gpr[0];
        wc.Ecx = (DWORD)st.gpr[1];
        wc.Edx = (DWORD)st.gpr[2];
        wc.Ebx = (DWORD)st.gpr[3];
        wc.Esp = (DWORD)st.gpr[4];
        wc.Ebp = (DWORD)st.gpr[5];
        wc.Esi = (DWORD)st.gpr[6];
        wc.Edi = (DWORD)st.gpr[7];
        wc.Eip = (DWORD)st.rip;
        wc.EFlags = (DWORD)st.rflags;
        wc.Dr0 = (DWORD)st.dr[0];
        wc.Dr1 = (DWORD)st.dr[1];
        wc.Dr2 = (DWORD)st.dr[2];
        wc.Dr3 = (DWORD)st.dr[3];
        wc.Dr6 = (DWORD)st.dr6;
        wc.Dr7 = (DWORD)st.dr7;
        *(uint32_t*)(wc.ExtendedRegisters + 24) = st.mxcsr;
        for (int i = 0; i < 8; ++i)
            memcpy(wc.ExtendedRegisters + 160 + i * 16, st.xmm[i], 16);
        if (!Wow64SetThreadContext(thread, &wc)) {
            err = fmt("Wow64SetThreadContext failed: %s", last_error_text().c_str());
            return false;
        }
        return true;
    }

    CONTEXT c;
    std::memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) {
        err = fmt("GetThreadContext failed: %s", last_error_text().c_str());
        return false;
    }
    c.Rax = st.gpr[0];
    c.Rcx = st.gpr[1];
    c.Rdx = st.gpr[2];
    c.Rbx = st.gpr[3];
    c.Rsp = st.gpr[4];
    c.Rbp = st.gpr[5];
    c.Rsi = st.gpr[6];
    c.Rdi = st.gpr[7];
    c.R8 = st.gpr[8];
    c.R9 = st.gpr[9];
    c.R10 = st.gpr[10];
    c.R11 = st.gpr[11];
    c.R12 = st.gpr[12];
    c.R13 = st.gpr[13];
    c.R14 = st.gpr[14];
    c.R15 = st.gpr[15];
    c.Rip = st.rip;
    c.EFlags = (DWORD)st.rflags;
    c.Dr0 = st.dr[0];
    c.Dr1 = st.dr[1];
    c.Dr2 = st.dr[2];
    c.Dr3 = st.dr[3];
    c.Dr6 = st.dr6;
    c.Dr7 = st.dr7;
    c.FltSave.MxCsr = st.mxcsr;
    for (int i = 0; i < 16; ++i)
        memcpy(&c.FltSave.XmmRegisters[i], st.xmm[i], 16);
    if (!SetThreadContext(thread, &c)) {
        err = fmt("SetThreadContext failed: %s", last_error_text().c_str());
        return false;
    }
    return true;
}

bool read_reg(const CpuState& st, const std::string& name, uint64_t& out) {
    int xi = xmm_index(name);
    if (xi >= 0) {  // low 64 bits of the xmm register
        if (xi >= st.xmm_count()) return false;
        std::memcpy(&out, st.xmm[xi], 8);
        return true;
    }
    if (to_lower(name) == "mxcsr") {
        out = st.mxcsr;
        return true;
    }
    const RegDef* d = find_reg(name, st.is32);
    if (!d) return false;
    // On x86 the 64-bit names are aliases for the low 32 bits.
    unsigned width = (st.is32 && d->width > 4) ? 4 : d->width;
    out = (raw_get(st, d->slot) >> d->shift) & width_mask(width);
    return true;
}

bool write_reg(CpuState& st, const std::string& name, uint64_t v) {
    int xi = xmm_index(name);
    if (xi >= 0) {  // writes the low 64 bits, keeps the high half
        if (xi >= st.xmm_count()) return false;
        std::memcpy(st.xmm[xi], &v, 8);
        return true;
    }
    if (to_lower(name) == "mxcsr") {
        st.mxcsr = (uint32_t)v;
        return true;
    }
    const RegDef* d = find_reg(name, st.is32);
    if (!d) return false;
    unsigned width = (st.is32 && d->width > 4) ? 4 : d->width;
    uint64_t mask = width_mask(width);
    v &= mask;
    uint64_t raw = raw_get(st, d->slot);
    uint64_t field_mask = mask << d->shift;
    raw = (raw & ~field_mask) | (v << d->shift);
    raw_set(st, d->slot, raw);
    return true;
}

int xmm_index(const std::string& name) {
    std::string n = to_lower(name);
    if (n.size() < 4 || n.compare(0, 3, "xmm") != 0) return -1;
    for (size_t i = 3; i < n.size(); ++i)
        if (n[i] < '0' || n[i] > '9') return -1;
    int idx = atoi(n.c_str() + 3);
    return (idx >= 0 && idx < 16) ? idx : -1;
}

bool read_xmm(const CpuState& st, int idx, uint8_t out[16]) {
    if (idx < 0 || idx >= st.xmm_count()) return false;
    std::memcpy(out, st.xmm[idx], 16);
    return true;
}

bool write_xmm(CpuState& st, int idx, const uint8_t in[16]) {
    if (idx < 0 || idx >= st.xmm_count()) return false;
    std::memcpy(st.xmm[idx], in, 16);
    return true;
}

std::string xmm_hex(const CpuState& st, int idx) {
    if (idx < 0 || idx >= st.xmm_count()) return "";
    return bytes_to_hex(st.xmm[idx], 16);
}

std::vector<std::string> reg_names(bool is32) {
    std::vector<std::string> out;
    for (const auto& r : kRegs) {
        if (is32 && r.x64only) continue;
        out.push_back(r.name);
    }
    out.push_back("mxcsr");
    int n = is32 ? 8 : 16;
    for (int i = 0; i < n; ++i) out.push_back(fmt("xmm%d", i));
    return out;
}

Json regs_json(const CpuState& st) {
    Json j = Json::obj();
    j.set_str("arch", st.is32 ? "x86" : "x64");

    Json gpr = Json::obj();
    const char* names64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    const char* names32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    if (st.is32) {
        for (int i = 0; i < 8; ++i) {
            uint64_t v = 0;
            read_reg(st, names32[i], v);
            gpr.set_hex(names32[i], v);
        }
    } else {
        for (int i = 0; i < 16; ++i) {
            uint64_t v = 0;
            read_reg(st, names64[i], v);
            gpr.set_hex(names64[i], v);
        }
    }
    uint64_t ip = 0, rf = 0;
    read_reg(st, st.is32 ? "eip" : "rip", ip);
    read_reg(st, "eflags", rf);
    gpr.set_hex(st.is32 ? "eip" : "rip", ip);
    j.set("gpr", gpr);

    Json fl = Json::obj();
    struct {
        const char* n;
        int bit;
    } flags[] = {{"CF", 0}, {"PF", 2}, {"AF", 4}, {"ZF", 6}, {"SF", 7},
                 {"TF", 8}, {"IF", 9}, {"DF", 10}, {"OF", 11}};
    for (auto& f : flags) fl.set_bool(f.n, (rf >> f.bit) & 1);
    fl.set_hex("raw", rf);
    j.set("rflags", fl);

    Json seg = Json::obj();
    const char* segs[] = {"cs", "ds", "es", "fs", "gs", "ss"};
    for (const char* s : segs) {
        uint64_t v = 0;
        read_reg(st, s, v);
        seg.set_u(s, v);
    }
    j.set("segments", seg);

    if (!st.is32) {
        Json dbg = Json::obj();
        for (int i = 0; i < 4; ++i) dbg.set_hex(fmt("dr%d", i), st.dr[i]);
        dbg.set_hex("dr6", st.dr6);
        dbg.set_hex("dr7", st.dr7);
        j.set("debug_registers", dbg);
    }

    Json sse = Json::obj();
    sse.set_hex("mxcsr", st.mxcsr);
    Json xarr = Json::arr();
    for (int i = 0; i < st.xmm_count(); ++i) xarr.push(Json::s(xmm_hex(st, i)));
    sse.set("xmm", std::move(xarr));
    j.set("sse", sse);
    return j;
}

std::string regs_text(const CpuState& st) {
    auto g = [&](const char* n) {
        uint64_t v = 0;
        read_reg(st, n, v);
        return v;
    };
    std::string out;
    if (st.is32) {
        out += fmt("EAX=%s EBX=%s ECX=%s EDX=%s\n", hex8(g("eax")).c_str(),
                   hex8(g("ebx")).c_str(), hex8(g("ecx")).c_str(), hex8(g("edx")).c_str());
        out += fmt("ESI=%s EDI=%s EBP=%s ESP=%s\n", hex8(g("esi")).c_str(),
                   hex8(g("edi")).c_str(), hex8(g("ebp")).c_str(), hex8(g("esp")).c_str());
        out += fmt("EIP=%s EFLAGS=%s", hex8(g("eip")).c_str(), hex8(g("eflags")).c_str());
    } else {
        out += fmt("RAX=%s RBX=%s RCX=%s RDX=%s\n", hex8(g("rax")).c_str(),
                   hex8(g("rbx")).c_str(), hex8(g("rcx")).c_str(), hex8(g("rdx")).c_str());
        out += fmt("RSI=%s RDI=%s RBP=%s RSP=%s\n", hex8(g("rsi")).c_str(),
                   hex8(g("rdi")).c_str(), hex8(g("rbp")).c_str(), hex8(g("rsp")).c_str());
        out += fmt("R8 =%s R9 =%s R10=%s R11=%s\n", hex8(g("r8")).c_str(),
                   hex8(g("r9")).c_str(), hex8(g("r10")).c_str(), hex8(g("r11")).c_str());
        out += fmt("R12=%s R13=%s R14=%s R15=%s\n", hex8(g("r12")).c_str(),
                   hex8(g("r13")).c_str(), hex8(g("r14")).c_str(), hex8(g("r15")).c_str());
        out += fmt("RIP=%s RFLAGS=%s", hex8(g("rip")).c_str(), hex8(g("rflags")).c_str());
    }

    uint64_t rf = g("eflags");
    std::string f;
    if (rf & 0x001) f += " CF";
    if (rf & 0x004) f += " PF";
    if (rf & 0x010) f += " AF";
    if (rf & 0x040) f += " ZF";
    if (rf & 0x080) f += " SF";
    if (rf & 0x100) f += " TF";
    if (rf & 0x400) f += " DF";
    if (rf & 0x800) f += " OF";
    out += "  [" + trim(f) + "]\n";

    out += fmt("MXCSR=%08X\n", st.mxcsr);
    for (int i = 0; i < st.xmm_count(); ++i)
        out += fmt("XMM%-2d=%s\n", i, xmm_hex(st, i).c_str());
    return out;
}

}  // namespace aj
