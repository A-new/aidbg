#pragma once
#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// One instruction that reaches an imported API through a memory operand, e.g.
//   call qword ptr [rip+0x1234]   -> reads the API pointer from that slot
// This is the shape VMProtect/Themida leave behind: references are scattered
// through the code instead of sitting in one tidy import table.
struct ImportRef {
    uint64_t insn_addr = 0;
    uint32_t insn_size = 0;
    uint32_t disp_offset = 0;   // where the displacement lives inside the instruction
    bool rip_relative = false;  // x64 [rip+disp32]; false = absolute [disp32]
    uint64_t slot_addr = 0;     // the pointer slot the instruction reads
    uint64_t api_addr = 0;      // the value currently stored there
    std::string module;
    std::string function;
    uint64_t ordinal = 0;
    bool resolved = false;
    std::string mnemonic;
};

struct ImportFixInput {
    std::function<bool(uint64_t addr, void* buf, size_t n, std::string& err)> read;
    std::function<bool(uint64_t addr, const void* buf, size_t n, std::string& err)> write;
    // api address -> module!function
    std::function<bool(uint64_t api, std::string& module, std::string& function,
                       uint64_t& ordinal)> resolve;
    bool is32 = false;
};

// Disassembles [start, end) and collects every instruction that reaches an
// imported API. This is the analysis half of the Wannabe Universal Import
// Fixer algorithm.
bool scan_import_refs(const ImportFixInput& in, uint64_t start, uint64_t end,
                      std::vector<ImportRef>& out, std::string& err);

// Gathers the scattered references into one contiguous import table at
// `new_base` and rewrites each instruction's displacement to point at its new
// slot. `pointer_size` is 8 on x64, 4 on x86.
bool fix_import_refs(const ImportFixInput& in, const std::vector<ImportRef>& refs,
                     uint64_t new_base, size_t pointer_size, Json& report, std::string& err);

Json import_refs_to_json(const std::vector<ImportRef>& refs);
std::string import_refs_to_text(const std::vector<ImportRef>& refs);

}  // namespace aj
