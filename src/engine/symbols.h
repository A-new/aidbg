#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// PDB/PE symbol access through DbgHelp (same approach as x64dbg and Nanomite).
class Symbols {
public:
    bool init(HANDLE proc, const std::string& search_path, std::string& err);
    void shutdown();

    bool load_module(uint64_t base, size_t size, const std::string& path,
                     const std::string& name, std::string& err);
    bool unload_module(uint64_t base);

    // "kernel32!CreateFileW", "kernel32+0x1234", "!entry", plain "main"
    bool resolve_name(const std::string& name, uint64_t& out, std::string& err);
    bool lookup_address(uint64_t addr, std::string& name, uint64_t& disp, std::string& err);
    // extent of the function containing `addr`, for control-flow recovery
    bool function_extent(uint64_t addr, uint64_t& start, uint64_t& end, std::string& name);
    bool line_from_address(uint64_t addr, std::string& file, uint32_t& line, uint64_t& disp);

    // mask like "CreateFile*" or "kernel32!*"; max caps the result for AI output
    Json enumerate(const std::string& mask, size_t max);

    bool ready() const { return ready_; }

private:
    HANDLE proc_ = nullptr;
    bool ready_ = false;
};

}  // namespace aj
