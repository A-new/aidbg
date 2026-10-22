#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// Normalized CPU state.
//
// The debugger itself is always a 64-bit process. For a WOW64 (x86) target the
// registers are read and written through Wow64Get/SetThreadContext, so the rest
// of the code base works with this one struct and never sees either native
// CONTEXT or WOW64_CONTEXT.
struct CpuState {
    bool is32 = false;  // true = x86 (WOW64) target

    // 0=rax/eax, 1=rcx/ecx, 2=rdx/edx, 3=rbx/ebx, 4=rsp/esp, 5=rbp/ebp,
    // 6=rsi/esi, 7=rdi/edi, 8..15=r8..r15 (x64 only)
    uint64_t gpr[16] = {};
    uint64_t rip = 0;
    uint64_t rflags = 0;
    uint16_t segs[6] = {};  // cs ds es fs gs ss

    uint64_t dr[4] = {};  // DR0..DR3
    uint64_t dr6 = 0;
    uint64_t dr7 = 0;

    // SSE state: x64 targets have xmm0-15, x86 targets xmm0-7 (kept in one
    // array so the rest of the code can index blindly)
    uint32_t mxcsr = 0;
    uint8_t xmm[16][16] = {};

    size_t pointer_size() const { return is32 ? 4 : 8; }
    int xmm_count() const { return is32 ? 8 : 16; }
};

bool get_state(HANDLE thread, bool is32, CpuState& out, std::string& err);
bool set_state(HANDLE thread, const CpuState& st, std::string& err);

// Register access by name. Accepts 64/32/16/8-bit views of the general purpose
// registers (including ah/ch/dh/bh), rip/eip, rflags/eflags and the segments.
// On an x86 target the 64-bit names (rax..r15) are accepted too and address the
// low 32 bits, so scripts stay portable across target bitness.
bool read_reg(const CpuState& st, const std::string& name, uint64_t& out);
bool write_reg(CpuState& st, const std::string& name, uint64_t v);

// SSE registers: "xmm0".."xmm15" as raw 16 bytes ("mxcsr" is a scalar and also
// works through read_reg/write_reg). read_reg/write_reg on an xmmN name address
// the low 64 bits so expressions like `xmm0` keep working.
int xmm_index(const std::string& name);  // -1 when not an xmm register
bool read_xmm(const CpuState& st, int idx, uint8_t out[16]);
bool write_xmm(CpuState& st, int idx, const uint8_t in[16]);
std::string xmm_hex(const CpuState& st, int idx);
std::vector<std::string> reg_names(bool is32);

Json regs_json(const CpuState& st);
std::string regs_text(const CpuState& st);

}  // namespace aj
