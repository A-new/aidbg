#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace aj {

// Thin Zydis wrapper. Gives us decoded instructions plus the classification
// needed for step-over / step-out decisions. Handles both x86 and x64 targets.
struct Insn {
    uint64_t address = 0;
    size_t length = 0;
    std::string text;       // "mov rax, qword ptr [rbx+0x10]"
    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;
    bool valid = false;

    bool is_call = false;
    bool is_ret = false;
    bool is_jump = false;        // unconditional
    bool is_cond_jump = false;
    bool is_int = false;         // int3 / int / ud2
    bool is_rep = false;
    bool is_loop = false;
    bool is_syscall = false;

    bool has_target = false;
    uint64_t target = 0;         // immediate branch target (absolute)
};

bool disasm_init(bool is32);
bool decode_one(const uint8_t* code, size_t len, uint64_t address, Insn& out, bool is32 = false);

// Fast path: how many bytes does the instruction at `address` occupy?
size_t insn_length(const uint8_t* code, size_t len, uint64_t address, bool is32 = false);

}  // namespace aj
