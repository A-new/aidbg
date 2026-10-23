#include "mcp/mcp_server.h"

#include <cstdio>
#include <exception>
#include <iostream>
#include <new>
#include <string>
#include <vector>

#include "output/output.h"
#include "util/json.h"
#include "util/json_parse.h"
#include "util/strutil.h"
#include "util/version.h"

namespace aj {
namespace {

using ToolFn = CmdResult (*)(Engine&, CliConfig&, const Json&, std::string&);

// ---------------------------------------------------------------- arg helpers

bool a_has(const Json& args, const char* key) {
    return !args.get(key).is_null();
}

std::string a_str(const Json& args, const char* key, const std::string& def = {}) {
    const Json& v = args.get(key);
    return v.is_null() ? def : v.as_str(def);
}

// Like a_str, but also accepts numbers and booleans. Tool clients naturally
// send addresses as JSON numbers; a_str() alone turned those into an empty
// string ("read <addr> <size>" with no address). Negative integers keep their
// sign instead of wrapping to a 20-digit unsigned value.
std::string a_text(const Json& args, const char* key, const std::string& def = {}) {
    const Json& v = args.get(key);
    switch (v.type()) {
        case Json::Type::Str: return v.as_str(def);
        case Json::Type::UInt: return std::to_string(v.as_u(0));
        case Json::Type::Int: return std::to_string(v.as_i(0));
        case Json::Type::Bool: return v.as_bool() ? "true" : "false";
        default: return def;
    }
}

// Accepts both a real boolean and the on/off strings used by the CLI.
bool a_bool(const Json& args, const char* key, bool def) {
    const Json& v = args.get(key);
    if (v.type() == Json::Type::Bool) return v.as_bool(def);
    if (v.type() == Json::Type::Str) {
        std::string s = to_lower(v.as_str());
        if (s == "on" || s == "true" || s == "1" || s == "yes") return true;
        if (s == "off" || s == "false" || s == "0" || s == "no") return false;
    }
    return def;
}

uint64_t a_u(const Json& args, const char* key, uint64_t def = 0) {
    const Json& v = args.get(key);
    return v.is_null() ? def : v.as_u(def);
}

// Joins a JSON string array into one command argument list.
std::string a_list(const Json& args, const char* key) {
    const Json& v = args.get(key);
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ' ';
        std::string item = v.at(i).as_str();
        if (item.find(' ') != std::string::npos) item = "\"" + item + "\"";
        out += item;
    }
    return out;
}

// ---------------------------------------------------------------- schema help

Json prop_string(const std::string& desc, const std::vector<std::string>& enums = {}) {
    Json p = Json::obj();
    p.set_str("type", "string");
    p.set_str("description", desc);
    if (!enums.empty()) {
        Json arr = Json::arr();
        for (auto& e : enums) arr.push(Json::s(e));
        p.set("enum", arr);
    }
    return p;
}

Json prop_number(const std::string& desc) {
    Json p = Json::obj();
    p.set_str("type", "integer");
    p.set_str("description", desc);
    return p;
}

Json prop_string_array(const std::string& desc) {
    Json p = Json::obj();
    p.set_str("type", "array");
    p.set_str("description", desc);
    Json items = Json::obj();
    items.set_str("type", "string");
    p.set("items", items);
    return p;
}

Json make_schema(const std::vector<std::pair<std::string, Json>>& props,
                 const std::vector<std::string>& required) {
    Json s = Json::obj();
    s.set_str("type", "object");
    Json properties = Json::obj();
    for (auto& kv : props) properties.set(kv.first, kv.second);
    s.set("properties", properties);
    if (!required.empty()) {
        Json req = Json::arr();
        for (auto& r : required) req.push(Json::s(r));
        s.set("required", req);
    }
    s.set_bool("additionalProperties", false);
    return s;
}

// ------------------------------------------------------------- tool handlers

CmdResult run(Engine& e, CliConfig& c, const std::string& line, std::string& name) {
    return dispatch(e, c, line, name);
}

CmdResult t_session(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action");
    if (action == "file") {
        std::string exe = a_str(a, "exe");
        if (exe.empty()) return CmdResult::fail("bad_args", "exe is required for action=file");
        // Set the target directly instead of building "file <path> args" and
        // splitting it on whitespace: any path containing a space used to be
        // cut in half, with the rest silently becoming arguments.
        c.exe = exe;
        c.args = a_str(a, "args");
        return run(e, c, "file", name);
    }
    if (action == "run") {
        std::string args = a_str(a, "args");
        if (!args.empty()) c.args = args;  // keep configured args otherwise
        return run(e, c, "run", name);
    }
    if (action == "attach") {
        if (!a_has(a, "pid"))
            return CmdResult::fail("bad_args", "pid is required for action=attach");
        return run(e, c, "attach " + std::to_string(a_u(a, "pid")), name);
    }
    return run(e, c, action, name);  // detach | kill | restart | info
}

CmdResult t_execute(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action");
    if (action == "until") {
        std::string addr = a_text(a, "address");
        if (addr.empty()) return CmdResult::fail("bad_args", "address is required for action=until");
        return run(e, c, "until " + addr, name);
    }
    if (action == "pause") {
        std::string line = "pause";
        if (a_has(a, "timeout_ms")) line += " " + std::to_string(a_u(a, "timeout_ms"));
        return run(e, c, line, name);
    }
    if (action == "stepuntil" || action == "rununtil") {
        std::string cond = a_str(a, "condition");
        if (cond.empty()) return CmdResult::fail("bad_args", "condition is required");
        std::string line = action + " " + cond;
        if (a_has(a, "max")) line += " max=" + std::to_string(a_u(a, "max"));
        return run(e, c, line, name);
    }
    if (action == "autostep") {
        std::string line = "autostep " + std::to_string(a_u(a, "count", 1));
        if (a_has(a, "delay_ms")) line += " " + std::to_string(a_u(a, "delay_ms"));
        return run(e, c, line, name);
    }
    std::string line = action;
    if (action == "continue") {
        if (a_has(a, "timeout_ms")) line += " " + std::to_string(a_u(a, "timeout_ms"));
    } else if (action == "step" || action == "next") {
        if (a_has(a, "count")) line += " " + std::to_string(a_u(a, "count"));
    }
    return run(e, c, line, name);
}

CmdResult t_breakpoint(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action");
    if (action == "list") return run(e, c, "bl", name);
    if (action == "enable" || action == "disable" || action == "delete" ||
        action == "condition") {
        if (!a_has(a, "id"))
            return CmdResult::fail("bad_args",
                                   "id is required for action=" + action +
                                       (action == "delete" ? " (use aidbg_command 'bc *' "
                                                             "to delete every breakpoint)"
                                                           : ""));
    }
    if (action == "enable") return run(e, c, "be " + std::to_string(a_u(a, "id")), name);
    if (action == "disable") return run(e, c, "bd " + std::to_string(a_u(a, "id")), name);
    if (action == "delete") return run(e, c, "bc " + std::to_string(a_u(a, "id")), name);
    if (action == "condition") {
        std::string cond = a_str(a, "condition");
        return run(e, c, "cond " + std::to_string(a_u(a, "id")) + " " + cond, name);
    }

    std::string target = a_text(a, "address");
    if (target.empty()) target = a_str(a, "symbol");
    if (target.empty()) return CmdResult::fail("bad_args", "address or symbol is required");

    std::string line;
    if (action == "hardware") {
        line = "hbreak " + target;
        bool has_access = a_has(a, "access"), has_size = a_has(a, "size");
        // size is positional after access; supply the default when only size
        // is given so it does not get parsed as an access string.
        if (has_access) line += " " + a_str(a, "access");
        else if (has_size) line += " x";
        if (has_size) line += " " + std::to_string(a_u(a, "size"));
    } else if (action == "memory") {
        line = "mbreak " + target + " " + std::to_string(a_u(a, "size", 4));
        if (a_has(a, "access")) line += " " + a_str(a, "access");
    } else {
        line = "break " + target;
        std::string cond = a_str(a, "condition");
        if (!cond.empty()) line += " " + cond;
    }
    return run(e, c, line, name);
}

CmdResult t_registers(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action", "read");
    if (action == "write") {
        return run(e, c, "setreg " + a_str(a, "name") + " " + a_text(a, "value"), name);
    }
    std::string line = "regs";
    std::string names = a_list(a, "names");
    if (!names.empty()) line += " " + names;
    return run(e, c, line, name);
}

CmdResult t_memory(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action");
    std::string addr = a_text(a, "address");

    if (action == "read") {
        if (addr.empty()) return CmdResult::fail("bad_args", "address is required for action=read");
        return run(e, c, "read " + addr + " " + std::to_string(a_u(a, "size", 64)), name);
    }
    if (action == "dump") {
        if (addr.empty()) return CmdResult::fail("bad_args", "address is required for action=dump");
        std::string line = "mem " + addr;
        if (a_has(a, "size")) line += " " + std::to_string(a_u(a, "size"));
        return run(e, c, line, name);
    }
    if (action == "write") {
        if (addr.empty()) return CmdResult::fail("bad_args", "address is required for action=write");
        return run(e, c, "write " + addr + " " + a_str(a, "bytes"), name);
    }
    if (action == "search") {
        std::string start = a_text(a, "start"), end = a_text(a, "end");
        std::string pattern = a_str(a, "pattern");
        if (start.empty() || end.empty() || pattern.empty())
            return CmdResult::fail("bad_args",
                                   "start, end and pattern are required for action=search");
        std::string line = "search " + start + " " + end + " " + pattern;
        if (a_has(a, "max")) line += " max=" + std::to_string(a_u(a, "max"));
        return run(e, c, line, name);
    }
    if (action == "regions") {
        std::string line = "regions";
        std::string start = a_text(a, "start"), end = a_text(a, "end");
        if (!start.empty()) line += " " + start;
        if (!end.empty()) {
            if (start.empty()) line += " 0";  // keep positional arguments aligned
            line += " " + end;
        }
        return run(e, c, line, name);
    }
    if (action == "alloc") return run(e, c, "alloc " + std::to_string(a_u(a, "size")), name);
    if (action == "free") {
        if (addr.empty()) return CmdResult::fail("bad_args", "address is required for action=free");
        return run(e, c, "free " + addr, name);
    }
    if (action == "protect") {
        if (addr.empty())
            return CmdResult::fail("bad_args", "address is required for action=protect");
        return run(e, c, "protect " + addr + " " + std::to_string(a_u(a, "size")) + " " +
                             a_str(a, "access", "rw"),
                   name);
    }
    return CmdResult::fail("bad_args", "unknown memory action: " + action);
}

CmdResult t_disasm(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string line = "disasm";
    std::string addr = a_text(a, "address");
    if (!addr.empty()) line += " " + addr;
    if (a_has(a, "count")) line += " " + std::to_string(a_u(a, "count"));
    return run(e, c, line, name);
}

CmdResult t_stack(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string line = "stack";
    if (a_has(a, "max")) line += " " + std::to_string(a_u(a, "max"));
    return run(e, c, line, name);
}

CmdResult t_cfg(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    // "max=N" is named so it cannot shift into the address position when the
    // caller only passes max_blocks.
    std::string line = "flow";
    std::string addr = a_text(a, "address");
    if (!addr.empty()) line += " " + addr;
    if (a_has(a, "max_blocks")) line += " max=" + std::to_string(a_u(a, "max_blocks"));
    return run(e, c, line, name);
}

CmdResult t_modules(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action", "modules");
    if (action == "thread") return run(e, c, "thread " + std::to_string(a_u(a, "tid")), name);
    if (action == "process") return run(e, c, "process " + std::to_string(a_u(a, "pid")), name);
    if (action == "symbols") {
        std::string line = "symbols";
        std::string mask = a_str(a, "mask");
        if (mask.empty() && a_has(a, "max")) mask = "*";  // keep max in its slot
        if (!mask.empty()) line += " " + mask;
        if (a_has(a, "max")) line += " " + std::to_string(a_u(a, "max"));
        return run(e, c, line, name);
    }
    return run(e, c, action, name);  // modules | threads | processes
}

CmdResult t_eval(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    return run(e, c, "eval " + a_str(a, "expression"), name);
}

CmdResult t_exceptions(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action", "list");
    if (action == "list") return run(e, c, "exlist", name);
    if (action == "ignore_all")
        return run(e, c, "exall " + std::string(a_bool(a, "enabled", false) ? "on" : "off"),
                   name);
    if (action == "set")
        return run(e, c, "exset " + a_str(a, "code") + " " + a_str(a, "policy", "break"), name);
    if (action == "delete") return run(e, c, "exdel " + a_str(a, "code"), name);
    return CmdResult::fail("bad_args", "unknown exception action: " + action);
}

CmdResult t_command(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    return run(e, c, a_str(a, "command"), name);
}

CmdResult t_snapshot(Engine& e, CliConfig& c, const Json& a, std::string& name) {
    std::string action = a_str(a, "action", "list");
    if (action == "stepback")
        return run(e, c, "stepback " + std::to_string(a_u(a, "count", 1)), name);

    std::string line = "snapshot " + action;
    if (action == "save" || action == "restore" || action == "delete") {
        std::string target = a_str(a, "name");
        // `snapshot delete` without a name would delete the newest capture
        // (the CLI treats an empty name as "current").
        if (action == "delete" && target.empty())
            return CmdResult::fail("bad_args", "name is required for action=delete");
        if (!target.empty()) line += " " + target;
    } else if (action == "auto") {
        line += " " + std::string(a_bool(a, "enabled", true) ? "on" : "off");
    }
    return run(e, c, line, name);
}

// --------------------------------------------------------------- tool catalog

struct ToolDef {
    const char* name;
    const char* description;
    Json (*schema)();
    ToolFn fn;
};

Json schema_session() {
    return make_schema({{"action", prop_string("What to do",
                                               {"file", "run", "attach", "detach", "kill",
                                                "restart", "info"})},
                        {"exe", prop_string("Path of the executable to debug (action=file)")},
                        {"args", prop_string("Command line arguments for the target")},
                        {"pid", prop_number("Process id (action=attach)")}},
                       {"action"});
}

Json schema_execute() {
    return make_schema(
        {{"action", prop_string("Execution control action",
                                {"continue", "pause", "step", "next", "finish", "until",
                                 "stepuntil", "rununtil", "autostep"})},
         {"count", prop_number("Number of steps (step/next, default 1)")},
         {"address", prop_string("Target address or expression (action=until)")},
         {"condition", prop_string("Expression evaluated at every stop (stepuntil/rununtil)")},
         {"max", prop_number("Step/stop budget before giving up (stepuntil/rununtil)")},
         {"delay_ms", prop_number("Pause between steps (action=autostep)")},
         {"timeout_ms", prop_number("Give up after this many ms instead of blocking forever")}},
        {"action"});
}

Json schema_breakpoint() {
    return make_schema(
        {{"action", prop_string("Breakpoint action",
                                {"add", "hardware", "memory", "condition", "list", "enable",
                                 "disable", "delete"})},
         {"address", prop_string("Address or expression")},
         {"symbol", prop_string("Symbol name, e.g. kernel32!CreateFileW")},
         {"id", prop_number("Breakpoint id")},
         {"condition", prop_string("Expression; the breakpoint stops only when it is non-zero")},
         {"access", prop_string("Access type", {"r", "w", "x", "rw", "rx", "wx", "rwx"})},
         {"size", prop_number("Watch size in bytes (1/2/4/8 for hardware, any for memory)")}},
        {"action"});
}

Json schema_registers() {
    return make_schema(
        {{"action", prop_string("read or write", {"read", "write"})},
         {"names", prop_string_array("Register names to read; omit for the full set")},
         {"name", prop_string("Register to write (action=write)")},
         {"value", prop_string("New value (action=write), expression accepted")}},
        {"action"});
}

Json schema_memory() {
    return make_schema(
        {{"action", prop_string("Memory action",
                                {"read", "dump", "write", "search", "regions", "alloc", "free",
                                 "protect"})},
         {"address", prop_string("Address or expression")},
         {"size", prop_number("Byte count")},
         {"bytes", prop_string("Hex bytes to write, e.g. '90 90' or '488B??90'")},
         {"start", prop_string("Range start (action=search/regions)")},
         {"end", prop_string("Range end (action=search/regions)")},
         {"pattern", prop_string("Byte pattern with ?? wildcards (action=search)")},
         {"max", prop_number("Maximum hits to return (action=search, default 64)")},
         {"access", prop_string("Page protection (action=protect)", {"r", "w", "x", "rw", "rx",
                                                                    "wx", "rwx"})}},
        {"action"});
}

Json schema_disasm() {
    return make_schema({{"address", prop_string("Start address; defaults to the instruction pointer")},
                        {"count", prop_number("How many instructions (default 8, max 256)")}},
                       {});
}

Json schema_stack() {
    return make_schema({{"max", prop_number("Maximum frames (default 32)")}}, {});
}

Json schema_cfg() {
    return make_schema(
        {{"address", prop_string("Address inside the function; defaults to the instruction pointer")},
         {"max_blocks", prop_number("Cap on basic blocks (default 64, max 512)")}},
        {});
}

Json schema_modules() {
    return make_schema(
        {{"action", prop_string("modules | threads | thread | processes | process | symbols",
                                {"modules", "threads", "thread", "processes", "process",
                                 "symbols"})},
         {"tid", prop_number("Thread id (action=thread)")},
         {"pid", prop_number("Process id (action=process)")},
         {"mask", prop_string("Symbol name mask, e.g. CreateFile* (action=symbols)")},
         {"max", prop_number("Maximum symbols (action=symbols, default 64)")}},
        {});
}

Json schema_eval() {
    return make_schema({{"expression", prop_string(
                            "Expression: hex/decimal, registers, symbols, module+0xoff, "
                            "[addr] dereference, arithmetic and comparisons")}},
                       {"expression"});
}

Json schema_exceptions() {
    return make_schema(
        {{"action", prop_string("list | set | delete | ignore_all",
                                {"list", "set", "delete", "ignore_all"})},
         {"code", prop_string("Exception code (0xC0000005) or alias (av, bp, ss, guard, cpp)")},
         {"policy", prop_string("What to do on a first-chance exception",
                                {"break", "ignore", "pass"})},
         {"enabled", prop_string("on or off (action=ignore_all)", {"on", "off"})}},
        {});
}

Json schema_command() {
    return make_schema(
        {{"command", prop_string("Any aidbg command line, e.g. 'search target.exe+0x0 "
                                 "target.exe+0x1000 48 8B ?? 90 max=8'")}},
        {"command"});
}

Json schema_snapshot() {
    return make_schema(
        {{"action", prop_string("save | restore | list | delete | clear | stepback",
                                {"save", "restore", "list", "delete", "clear", "stepback"})},
         {"name", prop_string("Snapshot name or index (save/restore/delete)")},
         {"count", prop_number("How many snapshots to go back (action=stepback, default 1)")},
         {"enabled", prop_string("on or off: capture a snapshot at every stop",
                                 {"on", "off"})}},
        {"action"});
}

const ToolDef kTools[] = {
    {"aidbg_session", "Start, attach or stop a debug session. A session is stateful: later "
                      "tool calls operate on the same target.",
     schema_session, t_session},
    {"aidbg_execute", "Control execution: continue, single step (into/over), finish the "
                      "current function, or run to an address.",
     schema_execute, t_execute},
    {"aidbg_breakpoint", "Manage software (INT3), hardware (DR0-DR3) and memory (guard page) "
                         "breakpoints. Breakpoints can carry an expression condition.",
     schema_breakpoint, t_breakpoint},
    {"aidbg_registers", "Read or write target registers. Names depend on the target "
                        "architecture (rax/rip for x64, eax/eip for x86).",
     schema_registers, t_registers},
    {"aidbg_memory", "Read, write, dump, search and inspect target memory.",
     schema_memory, t_memory},
    {"aidbg_disasm", "Disassemble target instructions with bytes, symbols and branch targets.",
     schema_disasm, t_disasm},
    {"aidbg_stack", "Show the call stack with symbols, module offsets and source lines.",
     schema_stack, t_stack},
    {"aidbg_cfg", "Control-flow graph of a function: basic blocks with their instructions and "
                  "the edges between them (fallthrough / branch / indirect). Use this to "
                  "understand a function's branching structure.",
     schema_cfg, t_cfg},
    {"aidbg_modules", "List loaded modules, threads, debuggee processes, or enumerate symbols. "
                      "A session can contain several processes (child-process following) and "
                      "mix x64 and x86 targets.",
     schema_modules, t_modules},
    {"aidbg_eval", "Evaluate an address expression in the target's context.",
     schema_eval, t_eval},
    {"aidbg_exceptions", "Inspect and configure how exceptions are reported.",
     schema_exceptions, t_exceptions},
    {"aidbg_snapshot", "Save and restore full process state (memory + registers) to move "
                       "backwards in time. stepback returns to an earlier capture; a snapshot "
                       "is captured automatically at every stop.",
     schema_snapshot, t_snapshot},
    {"aidbg_command", "Run any aidbg command line verbatim. Use this for anything the "
                      "dedicated tools do not cover.",
     schema_command, t_command},
};

// ------------------------------------------------------------- json-rpc plumbing

void write_message(const Json& msg) {
    std::string line = msg.dump();
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

Json make_result(const Json& id, Json result) {
    Json m = Json::obj();
    m.set_str("jsonrpc", "2.0");
    m.set("id", id);
    m.set("result", std::move(result));
    return m;
}

Json make_error(const Json& id, int code, const std::string& msg) {
    Json e = Json::obj();
    e.set_i("code", code);
    e.set_str("message", msg);
    Json m = Json::obj();
    m.set_str("jsonrpc", "2.0");
    m.set("id", id);
    m.set("error", e);
    return m;
}

// Turns a CmdResult into the MCP tools/call result payload.
Json tool_response(const CmdResult& r, const std::string& cmd_name, const SessionMeta& meta) {
    Json envelope = Json::obj();
    envelope.set_bool("ok", r.ok);
    envelope.set_str("cmd", cmd_name);
    if (r.ok) {
        envelope.set("data", r.data);
    } else {
        Json e = Json::obj();
        e.set_str("code", r.err_code);
        e.set_str("message", r.err_msg);
        envelope.set("error", e);
    }
    // Commands that have no structured data (help) only produce text; MCP
    // callers used to receive an empty object and no way to see it. When the
    // command already returned data, the text would just duplicate it.
    if (r.ok && r.data.size() == 0 && !r.text.empty()) envelope.set_str("text", r.text);
    envelope.set("session", meta.to_json());

    Json text = Json::obj();
    text.set_str("type", "text");
    text.set_str("text", envelope.dump());

    Json content = Json::arr();
    content.push(text);

    Json result = Json::obj();
    result.set("content", content);
    result.set_bool("isError", !r.ok);
    return result;
}

Json tools_list_result() {
    Json tools = Json::arr();
    for (const auto& t : kTools) {
        Json tool = Json::obj();
        tool.set_str("name", t.name);
        tool.set_str("description", t.description);
        tool.set("inputSchema", t.schema());
        tools.push(std::move(tool));
    }
    Json result = Json::obj();
    result.set("tools", tools);
    return result;
}

const ToolDef* find_tool(const std::string& name) {
    for (const auto& t : kTools)
        if (name == t.name) return &t;
    return nullptr;
}

constexpr size_t kMaxRequestBytes = 8u << 20;  // 8 MiB per JSON-RPC message

// Reads one newline-delimited message without ever buffering more than `max`
// bytes. std::getline would happily allocate a multi-gigabyte line first.
enum class LineRead { Eof, Ok, TooLong };
LineRead read_line_bounded(std::string& out, size_t max) {
    out.clear();
    char c = 0;
    bool any = false;
    while (std::cin.get(c)) {
        any = true;
        if (c == '\r') continue;
        if (c == '\n') return LineRead::Ok;
        if (out.size() >= max) {
            while (std::cin.get(c) && c != '\n') {
            }
            return LineRead::TooLong;
        }
        out += c;
    }
    return any ? LineRead::Ok : LineRead::Eof;
}

}  // namespace

void mcp_setup_engine(Engine& eng, CliConfig& cfg) {
    // stdout belongs to the protocol; direct command output must stay silent.
    Output::instance().set_quiet(true);
    Output::instance().set_json(true);

    // --hide was documented but ignored in MCP mode (main returned before
    // applying it); apply it here, where the engine actually lives.
    if (!cfg.hide_profile.empty()) {
        if (cfg.hide_profile == "off") {
            eng.hide.set_enabled(false);
        } else {
            HideConfig hc;
            if (hide_profile_config(cfg.hide_profile, hc))
                eng.hide.apply_config(hc, cfg.hide_profile);
        }
    }
    // on-hit commands run silently here (Output is quiet in MCP mode); their
    // side effects (labels, memory writes, ...) still apply
    eng.set_command_hook([&eng, &cfg](const std::string& cmd) {
        std::string cn;
        dispatch(eng, cfg, cmd, cn);
    });
}

Json mcp_handle_message(Engine& eng, CliConfig& cfg, const std::string& line,
                        bool& initialized) {
    try {
        Json req;
        std::string perr;
        if (!json_parse(line, req, perr))
            return make_error(Json::null(), -32700, "parse error: " + perr);
        if (req.type() != Json::Type::Obj) {
            // A top-level array is a JSON-RPC batch. Silently treating it
            // as a notification produced no response at all.
            return make_error(Json::null(), -32600, "batch requests are not supported");
        }

        Json id = req.get("id");
        bool is_notification = id.is_null();
        std::string method = req.get("method").as_str();
        std::string jsonrpc = req.get("jsonrpc").as_str();
        if (method.empty() || (!jsonrpc.empty() && jsonrpc != "2.0")) {
            if (!is_notification) return make_error(id, -32600, "invalid request");
            return Json::null();
        }

        if (method == "notifications/initialized" || method == "notifications/cancelled") {
            // Notifications with an id are still requests; answer them
            // instead of dropping the id on the floor.
            if (!is_notification) return make_result(id, Json::obj());
            return Json::null();
        }

        if (method == "initialize") {
            Json params = req.get("params");
            std::string client_version = params.get("protocolVersion").as_str();
            // Echo only versions we actually implement. Blindly echoing
            // whatever the client sent is not a valid negotiation.
            std::string version = "2025-06-18";
            if (client_version == "2024-11-05" || client_version == "2025-03-26" ||
                client_version == "2025-06-18")
                version = client_version;

            Json caps = Json::obj();
            caps.set("tools", Json::obj());
            Json info = Json::obj();
            info.set_str("name", "aidbg");
            info.set_str("version", AIDBG_VERSION);

            Json result = Json::obj();
            result.set_str("protocolVersion", version);
            result.set("capabilities", caps);
            result.set("serverInfo", info);
            result.set_str("instructions",
                           "aidbg is a debugger for Windows x86/x64. Typical flow: "
                           "aidbg_session(action=file/run) -> aidbg_execute -> inspect with "
                           "aidbg_registers / aidbg_disasm / aidbg_stack / aidbg_memory. "
                           "Addresses accept hex, registers, module+0xoff, module!symbol and "
                           "expressions. Responses use a stable JSON envelope with ok/cmd/data/"
                           "error/session.");
            initialized = true;
            if (!is_notification) return make_result(id, result);
            return Json::null();
        }

        if (method == "ping") {
            if (!is_notification) return make_result(id, Json::obj());
            return Json::null();
        }

        if (!initialized) {
            if (!is_notification) return make_error(id, -32002, "server not initialized");
            return Json::null();
        }

        if (method == "tools/list") {
            if (!is_notification) return make_result(id, tools_list_result());
            return Json::null();
        }

        if (method == "tools/call") {
            Json params = req.get("params");
            std::string tool_name = params.get("name").as_str();
            Json args = params.get("arguments");
            if (args.is_null()) args = Json::obj();

            const ToolDef* tool = find_tool(tool_name);
            if (!tool) {
                if (!is_notification) return make_error(id, -32602, "unknown tool: " + tool_name);
                return Json::null();
            }

            std::string cmd_name;
            CmdResult r = tool->fn(eng, cfg, args, cmd_name);
            if (cmd_name.empty()) {
                // Only fabricate "empty command" for a handler that
                // otherwise succeeded; a real bad_args message (e.g.
                // "exe is required") must survive.
                if (r.ok) r = CmdResult::fail("bad_args", "empty command");
                cmd_name = tool_name;
            }
            if (!is_notification)
                return make_result(id, tool_response(r, cmd_name, eng.session_meta()));
            return Json::null();
        }

        // Unknown methods are reported, but the connection stays alive.
        if (!is_notification) return make_error(id, -32601, "method not found: " + method);
        return Json::null();
    } catch (const std::bad_alloc&) {
        // A crafted request must not take the long-lived server down.
        return make_error(Json::null(), -32603, "out of memory");
    } catch (const std::exception& ex) {
        return make_error(Json::null(), -32603, std::string("internal error: ") + ex.what());
    } catch (...) {
        return make_error(Json::null(), -32603, "internal error");
    }
}

int run_mcp_server(CliConfig& cfg) {
    Engine eng;
    mcp_setup_engine(eng, cfg);

    bool initialized = false;
    std::string line;
    for (;;) {
        LineRead lr = read_line_bounded(line, kMaxRequestBytes);
        if (lr == LineRead::Eof) break;
        if (lr == LineRead::TooLong) {
            write_message(make_error(Json::null(), -32600, "request too large"));
            continue;
        }
        if (trim(line).empty()) continue;

        Json resp = mcp_handle_message(eng, cfg, line, initialized);
        if (!resp.is_null()) write_message(resp);
    }

    if (!eng.processes().empty()) {
        std::string err;
        eng.detach(err);
    }
    return 0;
}

}  // namespace aj
