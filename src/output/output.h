#pragma once
#include <string>

#include "util/json.h"

namespace aj {

// Snapshot of the debug session attached to every command response.
struct SessionMeta {
    bool active = false;
    uint32_t pid = 0;
    uint32_t tid = 0;               // current thread (0 = none)
    std::string state = "idle";     // idle | running | paused | exited
    std::string stop_reason;        // entry | breakpoint | step | exception | exit | ...
    std::string rip;
    std::string arch;               // x86 | x64
    size_t process_count = 1;       // debuggee processes in this session
    std::string detail;             // free-form, e.g. exception name

    Json to_json() const;
};

// Result of one command. Handlers fill `data` (machine readable) and `text`
// (human readable). In --json mode only `data` is printed; in text mode only
// `text` is printed. This keeps a single source of truth per command.
struct CmdResult {
    bool ok = true;
    std::string err_code;
    std::string err_msg;
    Json data = Json::obj();
    std::string text;

    static CmdResult fail(std::string code, std::string msg) {
        CmdResult r;
        r.ok = false;
        r.err_code = std::move(code);
        r.err_msg = std::move(msg);
        return r;
    }
};

class Output {
public:
    static Output& instance();

    void set_json(bool on) { json_ = on; }
    bool json() const { return json_; }
    void set_pretty(int indent) { indent_ = indent; }

    // When quiet, nothing is written to stdout. The MCP transport owns stdout
    // and builds its own responses from CmdResult, so direct writes would
    // corrupt the JSON-RPC stream.
    void set_quiet(bool on) { quiet_ = on; }

    // Prints exactly one response record for a finished command.
    void emit(const std::string& cmd, const CmdResult& r, const SessionMeta& meta);

    // Free-form notice that is not tied to a command result (module load, etc.)
    void event(const std::string& kind, const std::string& text, Json data = Json::obj());

private:
    bool json_ = false;
    bool quiet_ = false;
    int indent_ = 0;
};

}  // namespace aj
