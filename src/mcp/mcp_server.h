#pragma once

#include "cmd/commands.h"

namespace aj {

// Runs the MCP (Model Context Protocol) server on stdin/stdout until EOF.
// Transport: newline-delimited JSON-RPC 2.0, the standard MCP stdio transport.
//
// The engine instance lives for the whole session, so a debuggee started by one
// tool call is still there for the next one - which is the whole point of
// exposing a stateful debugger as MCP tools.
//
// Returns the process exit code.
int run_mcp_server(CliConfig& cfg);

}  // namespace aj
