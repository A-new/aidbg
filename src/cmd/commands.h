#pragma once
#include <string>
#include <vector>

#include "engine/engine.h"
#include "output/output.h"

namespace aj {

// Session-scoped CLI settings kept outside the engine so that the engine stays
// usable as a plain library (and later as an MCP tool backend).
struct CliConfig {
    std::string exe;
    std::string args;
    std::string cwd;
    bool json = false;
    bool new_console = false;
    bool follow_children = true;  // also debug processes spawned by the target
    bool fixed_base = true;       // disable ASLR so the image loads at its ImageBase
};

// Executes one command line. `cmd_name` receives the canonical command name so
// callers can put it into the JSON envelope.
CmdResult dispatch(Engine& eng, CliConfig& cfg, const std::string& line,
                   std::string& cmd_name);

// Machine readable command catalog, used by `help --json` and by MCP tool
// schema generation later on.
Json command_catalog();

}  // namespace aj
