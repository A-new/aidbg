#pragma once

#include <cstdint>
#include <string>

#include "cmd/commands.h"

namespace aj {

// MCP over HTTP for remote (dual-machine) debugging. One port serves both
// transports:
//   GET  /sse                          legacy SSE transport: the response is an
//                                       endless event stream whose first event
//                                       ("endpoint") names the POST URL
//   POST /messages?sessionId=<id>      legacy SSE transport message ingress
//   POST /mcp                          streamable HTTP transport: the JSON-RPC
//                                       reply comes back as the HTTP response
// Every request must carry the bearer token when one is configured.
//
// The debug engine is single-threaded by nature, so all JSON-RPC handling runs
// on one dispatcher thread; socket threads only move bytes and queue messages.
int run_mcp_http_server(CliConfig& cfg, const std::string& bind_addr, uint16_t port,
                        const std::string& token);

}  // namespace aj
