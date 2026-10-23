#pragma once
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// PDB/PE symbol access through DbgHelp (same approach as x64dbg and Nanomite).
//
// One DbgHelp session per debuggee process. A session used to be shared by
// every process in the debug, so a private module that loaded at different
// bases in different processes resolved against whichever copy DbgHelp saw
// last. DbgHelp keys everything by process handle, so the sessions are
// naturally independent; queries run against the *current* process
// (select(), kept in sync by the Engine).
class Symbols {
public:
    // Creates (or re-creates) the session for one debuggee. Call once per
    // process, including children.
    bool init(uint32_t pid, HANDLE proc, const std::string& search_path, std::string& err);
    // Ends every session (session teardown / detach).
    void shutdown();

    // Queries below run against this process's session.
    void select(uint32_t pid) { current_ = pid; }
    uint32_t current() const { return current_; }
    bool ready() const;

    bool load_module(uint32_t pid, uint64_t base, size_t size, const std::string& path,
                     const std::string& name, std::string& err);
    bool unload_module(uint32_t pid, uint64_t base);

    // "kernel32!CreateFileW", "kernel32+0x1234", "!entry", plain "main"
    bool resolve_name(const std::string& name, uint64_t& out, std::string& err);
    bool lookup_address(uint64_t addr, std::string& name, uint64_t& disp, std::string& err);
    // extent of the function containing `addr`, for control-flow recovery
    bool function_extent(uint64_t addr, uint64_t& start, uint64_t& end, std::string& name);
    bool line_from_address(uint64_t addr, std::string& file, uint32_t& line, uint64_t& disp);

    // mask like "CreateFile*" or "kernel32!*"; max caps the result for AI output
    Json enumerate(const std::string& mask, size_t max);

private:
    HANDLE cur() const;  // handle of the selected process, or null

    std::map<uint32_t, HANDLE> procs_;
    uint32_t current_ = 0;
};

}  // namespace aj
