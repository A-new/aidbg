#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "engine/disasm.h"
#include "util/json.h"

namespace aj {

struct CfgEdge {
    uint64_t from = 0;   // block start address
    uint64_t to = 0;     // block start address (or a target outside the function)
    std::string kind;    // fallthrough | branch | indirect
    bool external = false;
};

struct CfgBlock {
    uint64_t start = 0;
    uint64_t end = 0;                 // one past the last instruction
    std::vector<Insn> insns;
    std::string terminator;           // mnemonic of the last instruction
    std::vector<CfgEdge> edges;
    bool is_exit = false;             // ends in ret / ud2 / int
};

struct Cfg {
    std::string func_name;
    uint64_t func_start = 0;
    uint64_t func_end = 0;
    std::vector<CfgBlock> blocks;
    std::vector<CfgEdge> edges;
    size_t instruction_count = 0;
    bool truncated = false;           // stopped early (block budget or bad bytes)
};

// Everything the graph builder needs from the debugger, as callbacks so this
// file stays independent of the engine.
struct CfgInput {
    std::function<bool(uint64_t addr, void* buf, size_t n, std::string& err)> read;
    // function extent lookup; returns false when no symbol covers the address
    std::function<bool(uint64_t addr, uint64_t& start, uint64_t& end, std::string& name)> extent;
    std::function<std::string(uint64_t addr)> annotate;  // "module!sym+0x10", may be empty
    bool is32 = false;
};

// Builds the control-flow graph of the function containing `addr`.
bool build_cfg(const CfgInput& in, uint64_t addr, size_t max_blocks, Cfg& out,
               std::string& err);

Json cfg_to_json(const Cfg& c);
std::string cfg_to_text(const Cfg& c, bool with_instructions);

}  // namespace aj
