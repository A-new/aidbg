#include <windows.h>

#include <io.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "cmd/commands.h"
#include "engine/engine.h"
#include "mcp/mcp_server.h"
#include "output/output.h"
#include "util/strutil.h"
#include "util/version.h"

namespace {

void print_usage() {
    std::printf(
        "aidbg " AIDBG_VERSION " - AI-first command line debugger for Windows x64\n"
        "\n"
        "usage: aidbg [options] [command...]\n"
        "\n"
        "options:\n"
        "  --json              emit one JSON object per command (JSONL)\n"
        "  --pretty            pretty-print JSON output (implies --json)\n"
        "  -c, --cmd <line>    run a command; may be repeated\n"
        "  --script <file>     run commands from a file (one per line, # = comment)\n"
        "  --exe <path>        set the target executable\n"
        "  --args <string>     arguments passed to the target\n"
        "  --cwd <path>        working directory for the target\n"
        "  --console           give the target its own console window\n"
        "  --no-children       do not debug processes spawned by the target\n"
        "  --aslr              keep ASLR on (default: fixed base at the PE ImageBase)\n"
        "  --hide <profile>    anti-anti-debug profile (basic/standard/aggressive/vmp/\n"
        "                      themida/obsidium/off, default: standard)\n"
        "  --mcp               run as an MCP server over stdio (JSON-RPC, newline delimited)\n"
        "  --help              this text\n"
        "  --version           print version\n"
        "\n"
        "examples:\n"
        "  aidbg -c \"file demo.exe\" -c run -c \"break main\" -c continue -c regs\n"
        "  aidbg --json -c \"attach 1234\" -c \"search 0x400000 0x401000 488B??90\"\n"
        "  aidbg --script analysis.txt --json > result.jsonl\n"
        "\n"
        "run 'help' for the full command list\n");
}

// Executes a single line and prints exactly one response.
// Returns false when the session asked to quit.
bool run_line(aj::Engine& eng, aj::CliConfig& cfg, const std::string& line, bool& any_error) {
    std::string cmd_name;
    aj::CmdResult r = aj::dispatch(eng, cfg, line, cmd_name);
    if (cmd_name.empty()) return true;  // blank / comment line

    aj::Output::instance().emit(cmd_name, r, eng.session_meta());
    if (!r.ok) any_error = true;

    if (cmd_name == "help" && !cfg.json) {
        // text help already printed
    }
    return !(cmd_name == "quit");
}

bool run_file(aj::Engine& eng, aj::CliConfig& cfg, const std::string& path, bool& any_error) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "[error] cannot open script: %s\n", path.c_str());
        any_error = true;
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        if (!run_line(eng, cfg, line, any_error)) return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    aj::CliConfig cfg;
    std::vector<std::string> inline_cmds;
    std::vector<std::string> script_files;
    std::string tail_cmd;
    bool pretty = false;
    bool mcp_mode = false;
    std::string hide_profile_arg;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](std::string& out) -> bool {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };
        if (a == "--help" || a == "-h") {
            print_usage();
            return 0;
        } else if (a == "--version") {
            std::printf("aidbg " AIDBG_VERSION "\n");
            return 0;
        } else if (a == "--json") {
            cfg.json = true;
        } else if (a == "--console") {
            cfg.new_console = true;
        } else if (a == "--no-children") {
            cfg.follow_children = false;
        } else if (a == "--aslr") {
            cfg.fixed_base = false;
        } else if (a == "--mcp") {
            mcp_mode = true;
        } else if (a == "--pretty") {
            cfg.json = true;
            pretty = true;
        } else if (a == "-c" || a == "--cmd") {
            std::string s;
            if (!next(s)) {
                std::fprintf(stderr, "[error] %s requires a value\n", a.c_str());
                return 2;
            }
            inline_cmds.push_back(s);
        } else if (a == "--script") {
            std::string s;
            if (!next(s)) {
                std::fprintf(stderr, "[error] --script requires a value\n");
                return 2;
            }
            script_files.push_back(s);
        } else if (a == "--exe") {
            if (!next(cfg.exe)) {
                std::fprintf(stderr, "[error] --exe requires a value\n");
                return 2;
            }
        } else if (a == "--args") {
            if (!next(cfg.args)) {
                std::fprintf(stderr, "[error] --args requires a value\n");
                return 2;
            }
        } else if (a == "--cwd") {
            if (!next(cfg.cwd)) {
                std::fprintf(stderr, "[error] --cwd requires a value\n");
                return 2;
            }
        } else if (a == "--hide") {
            std::string s;
            if (!next(s)) {
                std::fprintf(stderr, "[error] --hide requires a value (profile name or 'off')\n");
                return 2;
            }
            hide_profile_arg = s;
        } else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "[error] unknown option: %s\n", a.c_str());
            return 2;
        } else {
            // everything after the first non-option is one command line
            tail_cmd.clear();
            for (int k = i; k < argc; ++k) {
                if (k > i) tail_cmd += ' ';
                tail_cmd += argv[k];
            }
            break;
        }
    }

    // MCP mode owns stdout entirely: serve JSON-RPC until stdin closes.
    if (mcp_mode) return aj::run_mcp_server(cfg);

    aj::Output::instance().set_json(cfg.json);
    if (pretty) aj::Output::instance().set_pretty(2);

    aj::Engine eng;
    bool any_error = false;

    // breakpoint on-hit commands run through the normal command pipeline
    eng.set_command_hook([&eng, &cfg](const std::string& line) {
        std::string cn;
        aj::CmdResult r = aj::dispatch(eng, cfg, line, cn);
        if (!cn.empty()) aj::Output::instance().emit(cn, r, eng.session_meta());
    });

    // anti-anti-debug profile selected on the command line
    if (!hide_profile_arg.empty()) {
        if (aj::to_lower(hide_profile_arg) == "off") {
            eng.hide.set_enabled(false);
        } else {
            aj::HideConfig hc;
            if (aj::hide_profile_config(hide_profile_arg, hc)) {
                eng.hide.apply_config(hc, aj::to_lower(hide_profile_arg));
            } else {
                std::fprintf(stderr, "[error] unknown hide profile: %s\n",
                             hide_profile_arg.c_str());
                return 2;
            }
        }
    }

    // 1) -c commands
    for (auto& c : inline_cmds) {
        if (!run_line(eng, cfg, c, any_error)) return any_error ? 1 : 0;
    }
    // 2) --script files
    for (auto& s : script_files) {
        if (!run_file(eng, cfg, s, any_error)) return any_error ? 1 : 0;
    }
    // 3) a bare command line given on argv
    if (!tail_cmd.empty()) {
        if (!run_line(eng, cfg, tail_cmd, any_error)) return any_error ? 1 : 0;
    }

    // 4) interactive / piped mode only when nothing else was requested
    bool batch_mode = !inline_cmds.empty() || !script_files.empty() || !tail_cmd.empty();
    if (batch_mode) {
        if (eng.active()) {
            std::string err;
            eng.detach(err);  // never leave a debuggee stuck when scripting
        }
        return any_error ? 1 : 0;
    }

    bool interactive = (GetConsoleWindow() != nullptr) && _isatty(_fileno(stdin));
    if (interactive && !cfg.json) {
        std::printf("aidbg " AIDBG_VERSION " - type 'help' for commands, 'quit' to exit\n");
    }

    std::string line;
    while (true) {
        if (interactive) {
            // Distinguish "a target is configured" from "a target is running" -
            // breakpoints can be set in both states, only inspection needs a
            // live session.
            std::string prompt;
            if (eng.active()) {
                prompt = aj::fmt("aidbg (pid %u, %s)> ", eng.pid(),
                                 eng.is_paused() ? "paused" : "running");
            } else if (!cfg.exe.empty()) {
                std::string name = cfg.exe;
                size_t slash = name.find_last_of("\\/");
                if (slash != std::string::npos) name = name.substr(slash + 1);
                prompt = aj::fmt("aidbg (%s, not started)> ", name.c_str());
            } else {
                prompt = "aidbg> ";
            }
            std::printf("%s", prompt.c_str());
            std::fflush(stdout);
        }
        if (!std::getline(std::cin, line)) break;
        if (!run_line(eng, cfg, line, any_error)) break;
    }

    if (eng.active()) {
        std::string err;
        eng.detach(err);
    }
    return any_error ? 1 : 0;
}
