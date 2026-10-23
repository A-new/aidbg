#pragma once

#include "cmd/commands.h"
#include "util/json.h"

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

// Runs the MCP server over HTTP(S-less) instead of stdio, so a client on
// another machine can drive the debugger: the legacy SSE transport (GET /sse
// + POST /messages?sessionId=...) and the streamable HTTP transport
// (POST /mcp) are served on the same port. `token` may be empty for loopback
// only; callers decide. Never returns under normal operation.
int run_mcp_http_server(CliConfig& cfg, const std::string& bind_addr, uint16_t port,
                        const std::string& token);

// Shared MCP plumbing (used by both transports) ------------------------------

// Engine + output wiring every MCP transport needs (hide profile, quiet
// output, silent on-hit commands).
void mcp_setup_engine(Engine& eng, CliConfig& cfg);

// Handles one JSON-RPC message (any transport). Returns the response to send,
// or a null Json when the message was a notification (nothing to send).
// `initialized` carries the handshake state across calls.
Json mcp_handle_message(Engine& eng, CliConfig& cfg, const std::string& line,
                        bool& initialized);

// Cryptographically random hex string (used for bearer tokens / session ids).
std::string mcp_random_hex(size_t nbytes);

}  // namespace aj
