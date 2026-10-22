#pragma once
#include <string>

#include "util/json.h"

namespace aj {

// Minimal JSON parser producing the same Json value tree used for output.
// Needed by the MCP transport, which is JSON-RPC over stdio.
bool json_parse(const std::string& text, Json& out, std::string& err);

}  // namespace aj
