#include "cmd/commands.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

#include "engine/cfg.h"
#include "engine/disasm.h"
#include "engine/exports.h"
#include "engine/importfix.h"
#include "engine/ntview.h"
#include "engine/pedump.h"
#include "util/strutil.h"

namespace aj {

namespace {

CmdResult ok(Json data, std::string text) {
    CmdResult r;
    r.data = std::move(data);
    r.text = std::move(text);
    return r;
}
CmdResult fail(const char* code, const std::string& msg) {
    return CmdResult::fail(code, msg);
}

std::string join_from(const std::vector<std::string>& a, size_t from) {
    std::string out;
    for (size_t i = from; i < a.size(); ++i) {
        if (i > from) out += ' ';
        out += a[i];
    }
    return out;
}

bool need_args(const std::vector<std::string>& a, size_t n, const char* usage) {
    if (a.size() >= n) return true;
    (void)usage;
    return false;
}

bool resolve(Engine& e, const std::string& text, uint64_t& addr, CmdResult& out) {
    std::string err;
    if (e.eval(text, addr, err)) return true;
    out = fail("bad_expression", err.empty() ? ("cannot resolve: " + text) : err);
    return false;
}

// Resolves `text` into bp.address. When it cannot be resolved (no target yet, or
// the symbol's module is not loaded) the breakpoint is kept as pending and
// resolved automatically once the target is up. Setting breakpoints before
// launching is a normal workflow, so this never fails.
void resolve_or_defer(Engine& e, Breakpoint& bp, const std::string& text) {
    bp.symbol = text;
    uint64_t addr = 0;
    std::string err;
    if (e.eval(text, addr, err) && addr) {
        bp.address = addr;
        bp.resolved = true;
    } else {
        bp.resolved = false;
    }
}

// ------------------------------------------------------------------ session

CmdResult cmd_help(Engine&, CliConfig& cfg, const std::vector<std::string>&) {
    if (cfg.json) {
        Json d = Json::obj();
        d.set("commands", command_catalog());
        return ok(d, {});
    }
    std::string t;
    t += "aidbg - AI-first command line debugger\n\n";
    t += "Session:\n";
    t += "  file <path>              set the executable to debug\n";
    t += "  run [args...]            launch and break at the entry point\n";
    t += "  attach <pid>             attach to a running process\n";
    t += "  detach | kill            detach cleanly, or terminate the target\n";
    t += "  restart                  kill and launch again with the same arguments\n";
    t += "  info | version           session state / version\n\n";
    t += "Execution:\n";
    t += "  continue|c|g [timeout]   resume execution\n";
    t += "  step|si [count]          single step (step into)\n";
    t += "  next|n|so [count]        step over calls\n";
    t += "  finish|gu                run until the current function returns\n";
    t += "  until <addr|expr>        run to an address\n\n";
    t += "Breakpoints:\n";
    t += "  break|b <addr|sym> [cond]        software breakpoint\n";
    t += "  hbreak <addr|sym> [r|w|x] [len]  hardware breakpoint (max 4)\n";
    t += "  mbreak <addr> <size> [r|w|x]     memory breakpoint (PAGE_GUARD)\n";
    t += "  cond <id> <expr>                 conditional breakpoint\n";
    t += "  bl | be <id> | bd <id> | bc <id|*>\n\n";
    t += "State:\n";
    t += "  regs [names...] | setreg <reg> <value>\n";
    t += "  mem <addr> [size] | read <addr> <size> | write <addr> <hexbytes>\n";
    t += "  search <start> <end> <pattern> [max=N]  byte search, ?? = wildcard\n";
    t += "  regions [start] [end] | alloc <size> | free <addr> | protect <addr> <size> <prot>\n\n";
    t += "Analysis:\n";
    t += "  disasm|u [addr] [count]   disassemble\n";
    t += "  modules | threads | thread <tid> | stack|bt [max]\n";
    t += "  symbols [mask] [max] | eval <expr>\n\n";
    t += "Exceptions:\n";
    t += "  exlist | exset <code> <break|ignore|pass> | exdel <code> | exall <on|off>\n\n";
    t += "Addresses accept hex (0x...), decimal, registers, module+0xoff, module!symbol\n";
    t += "and full expressions with [ ] dereferences. Use --json for machine output.\n";
    return ok(Json::obj(), t);
}

CmdResult cmd_file(Engine&, CliConfig& cfg, const std::vector<std::string>& a) {
    if (a.empty()) {
        Json d = Json::obj();
        d.set_str("exe", cfg.exe);
        d.set_str("args", cfg.args);
        d.set_str("cwd", cfg.cwd);
        return ok(d, fmt("target: %s %s\n", cfg.exe.c_str(), cfg.args.c_str()));
    }
    cfg.exe = a[0];
    cfg.args = join_from(a, 1);
    Json d = Json::obj();
    d.set_str("exe", cfg.exe);
    d.set_str("args", cfg.args);
    return ok(d, fmt("target set: %s %s\n", cfg.exe.c_str(), cfg.args.c_str()));
}

CmdResult cmd_run(Engine& e, CliConfig& cfg, const std::vector<std::string>& a) {
    if (!a.empty()) cfg.args = join_from(a, 0);
    if (cfg.exe.empty()) return fail("no_target", "no executable set; use: file <path>");
    if (e.active()) return fail("busy", "a target is already active");
    std::string err;
    if (!e.launch(cfg.exe, cfg.args, cfg.cwd, cfg.new_console, cfg.follow_children,
                  cfg.fixed_base, err))
        return fail("launch_failed", err);
    Json d = Json::obj();
    d.set_u("pid", e.pid());
    return ok(d, fmt("launched %s (pid %u) - stopped at %s\n", cfg.exe.c_str(), e.pid(),
                     e.stop_info().text.c_str()));
}

CmdResult cmd_attach(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "attach <pid>")) return fail("bad_args", "attach <pid>");
    uint64_t pid = 0;
    if (!parse_u64(a[0], pid)) return fail("bad_args", "invalid pid: " + a[0]);
    std::string err;
    if (!e.attach((uint32_t)pid, err)) return fail("attach_failed", err);
    Json d = Json::obj();
    d.set_u("pid", e.pid());
    return ok(d, fmt("attached to pid %u - stopped at %s\n", e.pid(),
                     e.stop_info().text.c_str()));
}

CmdResult cmd_detach(Engine& e, CliConfig&, const std::vector<std::string>&) {
    if (!e.active()) return fail("no_target", "no active target");
    uint32_t pid = e.pid();
    std::string err;
    if (!e.detach(err)) return fail("detach_failed", err);
    Json d = Json::obj();
    d.set_u("pid", pid);
    return ok(d, fmt("detached from pid %u\n", pid));
}

CmdResult cmd_kill(Engine& e, CliConfig&, const std::vector<std::string>&) {
    if (!e.active()) return fail("no_target", "no active target");
    uint32_t pid = e.pid();
    std::string err;
    if (!e.kill(err)) return fail("kill_failed", err);
    Json d = Json::obj();
    d.set_u("pid", pid);
    return ok(d, fmt("terminated pid %u\n", pid));
}

CmdResult cmd_restart(Engine& e, CliConfig& cfg, const std::vector<std::string>&) {
    if (e.active()) {
        std::string err;
        e.kill(err);
    }
    return cmd_run(e, cfg, {});
}

CmdResult cmd_aslr(Engine& e, CliConfig& cfg, const std::vector<std::string>& a) {
    if (a.empty()) {
        Json d = Json::obj();
        d.set_bool("fixed_base", cfg.fixed_base);
        d.set_str("mode", cfg.fixed_base ? "fixed" : "randomized");
        return ok(d, fmt("aslr: %s\n", cfg.fixed_base ? "off (fixed base)" : "on (randomized)"));
    }
    std::string v = to_lower(a[0]);
    if (v != "on" && v != "off" && v != "fixed" && v != "random")
        return fail("bad_args", "aslr <on|off>");
    cfg.fixed_base = (v == "off" || v == "fixed");
    Json d = Json::obj();
    d.set_bool("fixed_base", cfg.fixed_base);
    d.set_str("mode", cfg.fixed_base ? "fixed" : "randomized");
    if (e.active())
        return ok(d, "aslr setting changed; takes effect on the next 'run'\n");
    return ok(d, fmt("aslr: %s\n", cfg.fixed_base ? "off (fixed base)" : "on (randomized)"));
}

CmdResult cmd_info(Engine& e, CliConfig& cfg, const std::vector<std::string>&) {
    Json d = Json::obj();
    d.set_str("version", "aidbg 0.1.0");
    d.set_str("exe", cfg.exe);
    d.set_str("args", cfg.args);
    d.set_bool("target_active", e.active());
    if (e.active()) d.set_str("arch", e.arch_text());
    d.set_u("pid", e.pid());
    d.set_u("tid", e.tid());
    d.set("stop", e.stop_info().to_json());
    d.set_u("modules", e.modules().size());
    d.set_u("threads", e.threads().size());
    d.set_u("breakpoints", e.bps.all().size());
    std::string t = fmt("aidbg 0.1.0 | target: %s %s\n", cfg.exe.c_str(), cfg.args.c_str());
    if (e.active()) t += fmt("arch=%s\n", e.arch_text());
    t += fmt("pid=%u tid=%u modules=%zu threads=%zu breakpoints=%zu\n", e.pid(), e.tid(),
             e.modules().size(), e.threads().size(), e.bps.all().size());
    t += "stop: " + e.stop_info().text + "\n";
    return ok(d, t);
}

CmdResult cmd_version(Engine&, CliConfig&, const std::vector<std::string>&) {
    Json d = Json::obj();
    d.set_str("version", "0.1.0");
    d.set_str("disasm", "Zydis 4.1.1");
    d.set_str("symbols", "DbgHelp");
    return ok(d, "aidbg 0.1.0 (Zydis 4.1.1, DbgHelp)\n");
}

// --------------------------------------------------------------- execution

CmdResult cmd_cont(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.active()) return fail("no_target", "no active target");
    uint64_t tmo = 0;
    if (!a.empty() && !parse_u64(a[0], tmo)) return fail("bad_args", "usage: continue [timeout_ms]");
    std::string err;
    if (!e.resume(ResumeAction::Continue, 0, (uint32_t)tmo, err))
        return fail("resume_failed", err);
    Json d = Json::obj();
    d.set("stop", e.stop_info().to_json());
    return ok(d, "stopped: " + e.stop_info().text + "\n");
}

CmdResult run_steps(Engine& e, ResumeAction act, const std::vector<std::string>& a) {
    if (!e.active()) return fail("no_target", "no active target");
    uint64_t count = 1;
    if (!a.empty() && !parse_u64(a[0], count)) return fail("bad_args", "invalid count");
    if (count == 0) count = 1;
    if (count > 100000) return fail("bad_args", "count too large");
    std::string err;
    for (uint64_t i = 0; i < count; ++i) {
        if (!e.resume(act, 0, 0, err)) return fail("resume_failed", err);
        if (e.stop_info().reason == StopReason::Exit) break;
    }
    Json d = Json::obj();
    d.set("stop", e.stop_info().to_json());
    return ok(d, "stopped: " + e.stop_info().text + "\n");
}

CmdResult cmd_step(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    return run_steps(e, ResumeAction::StepInto, a);
}
CmdResult cmd_next(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    return run_steps(e, ResumeAction::StepOver, a);
}

CmdResult cmd_finish(Engine& e, CliConfig&, const std::vector<std::string>&) {
    if (!e.active()) return fail("no_target", "no active target");
    std::string err;
    if (!e.resume(ResumeAction::StepOut, 0, 0, err)) return fail("resume_failed", err);
    Json d = Json::obj();
    d.set("stop", e.stop_info().to_json());
    return ok(d, "stopped: " + e.stop_info().text + "\n");
}

CmdResult cmd_until(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "until <addr|expr>"))
        return fail("bad_args", "until <addr|expr>");
    uint64_t addr = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    std::string err;
    if (!e.resume(ResumeAction::RunUntil, addr, 0, err)) return fail("resume_failed", err);
    Json d = Json::obj();
    d.set("stop", e.stop_info().to_json());
    return ok(d, "stopped: " + e.stop_info().text + "\n");
}

// ------------------------------------------------------------ breakpoints

CmdResult cmd_break(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "break <addr|symbol> [condition]"))
        return fail("bad_args", "break <addr|symbol> [condition]");
    Breakpoint bp;
    bp.kind = BpKind::Software;
    if (a.size() > 1) bp.condition = join_from(a, 1);
    resolve_or_defer(e, bp, a[0]);

    std::string err;
    int id = e.bps.add(bp);
    Breakpoint* p = e.bps.find(id);
    if (p && p->resolved) {
        if (!e.apply_breakpoint(*p, err)) {
            e.bps.remove(id);
            return fail("breakpoint_failed", err);
        }
    }
    Json d = Json::obj();
    d.set_u("id", id);
    d.set_hex("address", p ? p->address : 0);
    d.set_bool("resolved", p ? p->resolved : false);
    if (p && !p->condition.empty()) d.set_str("condition", p->condition);
    return ok(d, fmt("breakpoint %d set at %s%s\n", id, hex8(p ? p->address : 0).c_str(),
                     (p && !p->resolved) ? " (pending, resolves on start)" : ""));
}

CmdResult cmd_hbreak(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "hbreak <addr|symbol> [r|w|x] [size]"))
        return fail("bad_args", "hbreak <addr|symbol> [r|w|x] [size]");
    Breakpoint bp;
    bp.kind = BpKind::Hardware;
    bp.size = 1;
    bp.access = BP_ACC_EXEC;
    resolve_or_defer(e, bp, a[0]);
    if (a.size() > 1) {
        std::string m = to_lower(a[1]);
        uint8_t acc = 0;
        for (char c : m) {
            if (c == 'r') acc |= BP_ACC_READ;
            else if (c == 'w') acc |= BP_ACC_WRITE;
            else if (c == 'x') acc |= BP_ACC_EXEC;
            else return fail("bad_args", "access must be r/w/x");
        }
        bp.access = acc ? acc : BP_ACC_EXEC;
    }
    if (a.size() > 2) {
        uint64_t sz = 1;
        if (!parse_u64(a[2], sz) || (sz != 1 && sz != 2 && sz != 4 && sz != 8))
            return fail("bad_args", "size must be 1, 2, 4 or 8");
        bp.size = (size_t)sz;
    }
    std::string err;
    int id = e.bps.add(bp);
    Breakpoint* p = e.bps.find(id);
    if (!e.apply_breakpoint(*p, err)) {
        e.bps.remove(id);
        return fail("breakpoint_failed", err);
    }
    Json d = Json::obj();
    d.set_u("id", id);
    d.set_hex("address", p->address);
    d.set_str("access", p->access_text());
    d.set_u("size", (uint64_t)p->size);
    d.set_bool("resolved", p->resolved);
    return ok(d, fmt("hardware breakpoint %d at %s (%s, len %zu)%s\n", id,
                     hex8(p->address).c_str(), p->access_text().c_str(), p->size,
                     p->resolved ? "" : " (pending, resolves on start)"));
}

CmdResult cmd_mbreak(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 2, "mbreak <addr> <size> [r|w|x]"))
        return fail("bad_args", "mbreak <addr> <size> [r|w|x]");
    Breakpoint bp;
    bp.kind = BpKind::Memory;
    bp.access = BP_ACC_READ | BP_ACC_WRITE;
    uint64_t sz = 0;
    if (!parse_u64(a[1], sz) || sz == 0) return fail("bad_args", "invalid size");
    resolve_or_defer(e, bp, a[0]);
    bp.size = (size_t)sz;
    if (a.size() > 2) {
        std::string m = to_lower(a[2]);
        uint8_t acc = 0;
        for (char c : m) {
            if (c == 'r') acc |= BP_ACC_READ;
            else if (c == 'w') acc |= BP_ACC_WRITE;
            else if (c == 'x') acc |= BP_ACC_EXEC;
        }
        if (acc) bp.access = acc;
    }
    std::string err;
    int id = e.bps.add(bp);
    Breakpoint* p = e.bps.find(id);
    if (!e.apply_breakpoint(*p, err)) {
        e.bps.remove(id);
        return fail("breakpoint_failed", err);
    }
    Json d = Json::obj();
    d.set_u("id", id);
    d.set_hex("address", p->address);
    d.set_u("size", (uint64_t)p->size);
    d.set_str("access", p->access_text());
    d.set_bool("resolved", p->resolved);
    return ok(d, fmt("memory breakpoint %d at %s size %zu (%s)%s\n", id,
                     hex8(p->address).c_str(), p->size, p->access_text().c_str(),
                     p->resolved ? "" : " (pending, resolves on start)"));
}

CmdResult cmd_cond(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 2, "cond <id> <expression>"))
        return fail("bad_args", "cond <id> <expression>");
    uint64_t id = 0;
    if (!parse_u64(a[0], id)) return fail("bad_args", "invalid breakpoint id");
    Breakpoint* bp = e.bps.find((int)id);
    if (!bp) return fail("not_found", "no such breakpoint: " + a[0]);
    bp->condition = join_from(a, 1);
    Json d = Json::obj();
    d.set_u("id", id);
    d.set_str("condition", bp->condition);
    return ok(d, fmt("breakpoint %llu condition set to: %s\n", (unsigned long long)id,
                     bp->condition.c_str()));
}

CmdResult cmd_bl(Engine& e, CliConfig&, const std::vector<std::string>&) {
    Json d = Json::obj();
    d.set("breakpoints", e.bps.to_json());
    return ok(d, e.bps.to_text());
}

CmdResult bp_toggle(Engine& e, const std::vector<std::string>& a, bool enable) {
    if (!need_args(a, 1, "<id>")) return fail("bad_args", "missing id");
    uint64_t id = 0;
    if (!parse_u64(a[0], id)) return fail("bad_args", "invalid id");
    std::string err;
    if (!e.set_breakpoint_enabled((int)id, enable, err)) return fail("bp_failed", err);
    Json d = Json::obj();
    d.set_u("id", id);
    d.set_bool("enabled", enable);
    return ok(d, fmt("breakpoint %llu %s\n", (unsigned long long)id,
                     enable ? "enabled" : "disabled"));
}

CmdResult cmd_be(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    return bp_toggle(e, a, true);
}
CmdResult cmd_bd(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    return bp_toggle(e, a, false);
}

CmdResult cmd_bc(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "delete <id|*>"))
        return fail("bad_args", "delete <id|*>");
    std::string err;
    if (a[0] == "*") {
        std::vector<int> ids;
        for (auto& bp : e.bps.all()) ids.push_back(bp.id);
        for (int id : ids) e.remove_breakpoint(id, err);
        Json d = Json::obj();
        d.set_u("removed", ids.size());
        return ok(d, fmt("removed %zu breakpoints\n", ids.size()));
    }
    uint64_t id = 0;
    if (!parse_u64(a[0], id)) return fail("bad_args", "invalid id");
    if (!e.remove_breakpoint((int)id, err)) return fail("bp_failed", err);
    Json d = Json::obj();
    d.set_u("id", id);
    return ok(d, fmt("breakpoint %llu removed\n", (unsigned long long)id));
}

// ------------------------------------------------------------------- state

CmdResult cmd_regs(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    CpuState st;
    std::string err;
    if (!e.get_state(st, err)) return fail("regs_failed", err);
    if (a.empty()) return ok(regs_json(st), regs_text(st));

    Json d = Json::obj();
    d.set_str("arch", e.arch_text());
    std::string t;
    for (auto& n : a) {
        int xi = xmm_index(n);
        if (xi >= 0) {  // full 128-bit view, byte order as displayed
            std::string hx = xmm_hex(st, xi);
            if (hx.empty()) return fail("bad_register", "no such xmm register: " + n);
            d.set_str(to_lower(n), hx);
            t += fmt("%s = %s\n", n.c_str(), hx.c_str());
            continue;
        }
        uint64_t v = 0;
        if (!read_reg(st, n, v)) return fail("bad_register", "unknown register: " + n);
        d.set_hex(to_lower(n), v);
        t += fmt("%s = %s\n", n.c_str(), hex8(v).c_str());
    }
    return ok(d, t);
}

CmdResult cmd_setreg(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 2, "setreg <register> <value>"))
        return fail("bad_args", "setreg <register> <value>");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    CpuState st;
    std::string err;
    if (!e.get_state(st, err)) return fail("regs_failed", err);

    int xi = xmm_index(a[0]);
    if (xi >= 0) {
        // raw byte string in the exact order `regs xmmN` prints (up to 32 hex
        // digits, shorter fills the low bytes, the rest is zeroed)
        std::string hs = a[1];
        if (hs.size() > 2 && hs[0] == '0' && (hs[1] == 'x' || hs[1] == 'X')) hs = hs.substr(2);
        if (hs.empty() || hs.size() > 32 || hs.size() % 2 != 0)
            return fail("bad_args", "xmm value must be 1..32 hex digits (even count)");
        uint8_t bytes[16] = {0};
        for (size_t i = 0; i < hs.size(); i += 2) {
            unsigned b = 0;
            if (sscanf(hs.c_str() + i, "%2x", &b) != 1)
                return fail("bad_args", "invalid hex: " + a[1]);
            bytes[i / 2] = (uint8_t)b;
        }
        if (!write_xmm(st, xi, bytes)) return fail("bad_register", "no such xmm register: " + a[0]);
        if (!e.set_state(st, err)) return fail("regs_failed", err);
        Json d = Json::obj();
        d.set_str("register", to_lower(a[0]));
        d.set_str("value", xmm_hex(st, xi));
        return ok(d, fmt("%s = %s\n", a[0].c_str(), xmm_hex(st, xi).c_str()));
    }

    uint64_t v = 0;
    CmdResult dummy;
    if (!resolve(e, a[1], v, dummy)) return dummy;
    if (!write_reg(st, a[0], v)) return fail("bad_register", "unknown register: " + a[0]);
    if (!e.set_state(st, err)) return fail("regs_failed", err);
    Json d = Json::obj();
    d.set_str("register", to_lower(a[0]));
    d.set_hex("value", v);
    return ok(d, fmt("%s = %s\n", a[0].c_str(), hex8(v).c_str()));
}

CmdResult cmd_mem(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "mem <addr> [size]"))
        return fail("bad_args", "mem <addr> [size]");
    uint64_t addr = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    uint64_t size = 64;
    if (a.size() > 1 && !parse_u64(a[1], size)) return fail("bad_args", "invalid size");
    if (size == 0 || size > 4096) return fail("bad_args", "size must be 1..4096");
    std::string err;
    std::string dump = hexdump(e.process(), addr, (size_t)size, err);
    if (dump.empty() && !err.empty()) return fail("read_failed", err);

    std::vector<uint8_t> buf((size_t)size);
    size_t got = 0;
    read_memory(e.process(), addr, buf.data(), (size_t)size, err, &got);
    Json d = Json::obj();
    d.set_hex("address", addr);
    d.set_u("size", (uint64_t)got);
    d.set_str("bytes", bytes_to_hex(buf.data(), got));
    return ok(d, dump);
}

CmdResult cmd_read(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 2, "read <addr> <size>"))
        return fail("bad_args", "read <addr> <size>");
    uint64_t addr = 0, size = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    if (!parse_u64(a[1], size) || size == 0 || size > 65536)
        return fail("bad_args", "invalid size (1..65536)");
    std::vector<uint8_t> buf((size_t)size);
    std::string err;
    size_t got = 0;
    if (!read_memory(e.process(), addr, buf.data(), (size_t)size, err, &got))
        return fail("read_failed", err);
    Json d = Json::obj();
    d.set_hex("address", addr);
    d.set_u("size", (uint64_t)got);
    d.set_str("bytes", bytes_to_hex(buf.data(), got));
    return ok(d, bytes_to_hex(buf.data(), got) + "\n");
}

CmdResult cmd_write(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 2, "write <addr> <hexbytes>"))
        return fail("bad_args", "write <addr> <hexbytes>");
    uint64_t addr = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;
    if (!parse_pattern(join_from(a, 1), bytes, mask))
        return fail("bad_args", "invalid byte pattern");
    for (bool m : mask)
        if (!m) return fail("bad_args", "wildcards are not allowed when writing");
    std::string err;
    if (!write_memory(e.process(), addr, bytes.data(), bytes.size(), err))
        return fail("write_failed", err);
    Json d = Json::obj();
    d.set_hex("address", addr);
    d.set_u("written", bytes.size());
    return ok(d, fmt("wrote %zu bytes at %s\n", bytes.size(), hex8(addr).c_str()));
}

CmdResult cmd_search(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 3, "search <start> <end> <pattern> [max=N]"))
        return fail("bad_args", "search <start> <end> <pattern> [max=N]");
    uint64_t start = 0, end = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], start, dummy)) return dummy;
    if (!resolve(e, a[1], end, dummy)) return dummy;

    // Everything after the range is the pattern, so `61 69 64` works without
    // quoting. An optional trailing `max=N` caps the number of hits.
    std::string pattern_text;
    uint64_t max_hits = 64;
    for (size_t i = 2; i < a.size(); ++i) {
        const std::string& t = a[i];
        if (starts_with(t, "max=") || starts_with(t, "max:")) {
            if (!parse_u64(t.substr(4), max_hits)) return fail("bad_args", "invalid max");
            continue;
        }
        if (!pattern_text.empty()) pattern_text += ' ';
        pattern_text += t;
    }
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;
    if (!parse_pattern(pattern_text, bytes, mask))
        return fail("bad_args",
                    "invalid pattern: use hex bytes ('48 8B ?? 90' or '488B??90'), "
                    "wildcard is ??");
    if (max_hits == 0 || max_hits > 10000) max_hits = 10000;

    std::vector<uint64_t> hits;
    std::string err;
    if (!search_memory(e.process(), start, end, bytes, mask, (size_t)max_hits, hits, err))
        return fail("search_failed", err);
    Json arr = Json::arr();
    std::string t;
    for (uint64_t h : hits) {
        arr.push(Json::hex(h));
        t += hex8(h) + "\n";
    }
    Json d = Json::obj();
    d.set("hits", arr);
    d.set_u("count", hits.size());
    d.set_u("max", max_hits);
    d.set_str("pattern", bytes_to_hex(bytes));
    d.set_hex("range_start", start);
    d.set_hex("range_end", end);
    return ok(d, hits.empty() ? "no matches\n"
                              : fmt("%zu match(es):\n", hits.size()) + t);
}

CmdResult cmd_regions(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    uint64_t start = 0, end = 0;
    if (a.size() > 0) {
        CmdResult dummy;
        if (!resolve(e, a[0], start, dummy)) return dummy;
    }
    if (a.size() > 1) {
        CmdResult dummy;
        if (!resolve(e, a[1], end, dummy)) return dummy;
    }
    auto regs = query_regions(e.process(), start, end);
    Json arr = Json::arr();
    std::string t = fmt("%-18s %-10s %-8s %-8s %s\n", "base", "size", "protect", "state",
                        "module");
    t += std::string(60, '-') + "\n";
    for (auto& r : regs) {
        if (r.state == MEM_FREE) continue;  // free address space is just noise
        const ModuleInfo* m = e.module_at(r.base);
        if (m) r.module = m->name;
        arr.push(region_json(r));
        t += fmt("%-18s %-10s %-8s %-8s %s\n", hex8(r.base).c_str(),
                 fmt("0x%zx", r.size).c_str(), protect_text(r.protect).c_str(),
                 state_text(r.state).c_str(), r.module.c_str());
    }
    Json d = Json::obj();
    d.set("regions", arr);
    d.set_u("count", regs.size());
    return ok(d, t);
}

CmdResult cmd_alloc(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "alloc <size>"))
        return fail("bad_args", "alloc <size>");
    uint64_t size = 0;
    if (!parse_u64(a[0], size) || size == 0) return fail("bad_args", "invalid size");
    uint64_t addr = 0;
    std::string err;
    if (!alloc_memory(e.process(), (size_t)size, addr, err)) return fail("alloc_failed", err);
    Json d = Json::obj();
    d.set_hex("address", addr);
    d.set_u("size", size);
    return ok(d, fmt("allocated %llu bytes at %s\n", (unsigned long long)size,
                     hex8(addr).c_str()));
}

CmdResult cmd_free(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "free <addr>"))
        return fail("bad_args", "free <addr>");
    uint64_t addr = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    std::string err;
    if (!free_memory(e.process(), addr, err)) return fail("free_failed", err);
    Json d = Json::obj();
    d.set_hex("address", addr);
    return ok(d, fmt("freed %s\n", hex8(addr).c_str()));
}

CmdResult cmd_protect(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 3, "protect <addr> <size> <r|w|x|rw|rx|wx|rwx>"))
        return fail("bad_args", "protect <addr> <size> <r|w|x|...>");
    uint64_t addr = 0, size = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    if (!parse_u64(a[1], size) || size == 0) return fail("bad_args", "invalid size");
    std::string m = to_lower(a[2]);
    bool r = m.find('r') != std::string::npos;
    bool w = m.find('w') != std::string::npos;
    bool x = m.find('x') != std::string::npos;
    DWORD prot = PAGE_NOACCESS;
    if (x && w)
        prot = PAGE_EXECUTE_READWRITE;
    else if (x && r)
        prot = PAGE_EXECUTE_READ;
    else if (x)
        prot = PAGE_EXECUTE;
    else if (w)
        prot = PAGE_READWRITE;
    else if (r)
        prot = PAGE_READONLY;
    DWORD old = 0;
    std::string err;
    if (!protect_memory(e.process(), addr, (size_t)size, prot, old, err))
        return fail("protect_failed", err);
    Json d = Json::obj();
    d.set_hex("address", addr);
    d.set_u("size", size);
    d.set_str("protect", protect_text(prot));
    d.set_u("old_protect", old);
    return ok(d, fmt("protection at %s set to %s\n", hex8(addr).c_str(),
                     protect_text(prot).c_str()));
}

// ---------------------------------------------------------------- analysis

CmdResult cmd_disasm(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    uint64_t addr = 0;
    uint64_t count = 8;
    bool have_addr = false;

    if (!a.empty()) {
        // A lone small integer is a count, not an address: real x64 addresses
        // are far above 4096, and `disasm 6` should mean "6 instructions".
        uint64_t v = 0;
        bool numeric = parse_u64(a[0], v);
        if (a.size() == 1 && numeric && v > 0 && v <= 4096 && e.is_paused()) {
            count = v;
        } else {
            CmdResult dummy;
            if (!resolve(e, a[0], addr, dummy)) return dummy;
            have_addr = true;
            if (a.size() > 1 && !parse_u64(a[1], count))
                return fail("bad_args", "invalid count");
        }
    }
    if (!have_addr) {
        if (!e.is_paused())
            return fail("not_paused", "target is not paused (specify an address)");
        CpuState st;
        std::string err;
        if (!e.get_state(st, err)) return fail("disasm_failed", err);
        addr = st.rip;
    }
    if (count == 0 || count > 256) return fail("bad_args", "count must be 1..256");

    std::vector<uint8_t> buf((size_t)count * 16 + 32);
    std::string err;
    size_t got = 0;
    if (!read_memory(e.process(), addr, buf.data(), buf.size(), err, &got))
        return fail("read_failed", err);

    Json arr = Json::arr();
    std::string t;
    uint64_t cur = addr;
    size_t off = 0;
    for (uint64_t i = 0; i < count && off + 1 < got;) {
        Insn insn;
        if (!decode_one(buf.data() + off, got - off, cur, insn, e.is32())) {
            t += fmt("%s  ??\n", hex8(cur).c_str());
            Json j = Json::obj();
            j.set_hex("address", cur);
            j.set_bool("valid", false);
            arr.push(std::move(j));
            off += 1;
            cur += 1;
            continue;
        }
        std::string comment;
        if (insn.has_target) {
            std::string sym;
            uint64_t disp = 0;
            if (e.sym.lookup_address(insn.target, sym, disp, err)) {
                comment = sym + (disp ? fmt("+0x%llx", (unsigned long long)disp) : "");
            } else {
                const ModuleInfo* m = e.module_at(insn.target);
                if (m) comment = fmt("%s+0x%llx", m->name.c_str(),
                                     (unsigned long long)(insn.target - m->base));
            }
        }
        // user label / comment anchored at this instruction
        std::string note_label, note_text;
        {
            const ModuleInfo* mn = e.module_at(cur);
            const Note* nt = mn ? e.notes.find(mn->name, cur - mn->base) : nullptr;
            if (nt) {
                note_label = nt->label;
                note_text = nt->comment;
            }
        }
        std::string annot;
        if (!note_label.empty()) annot = note_label + ":";
        if (!note_text.empty()) annot += (annot.empty() ? "" : " ") + note_text;
        if (!annot.empty()) comment = comment.empty() ? annot : comment + " | " + annot;
        Json j = Json::obj();
        j.set_hex("address", cur);
        j.set_str("bytes", bytes_to_hex(insn.bytes));
        j.set_str("text", insn.text);
        j.set_str("mnemonic", insn.mnemonic);
        j.set_str("operands", insn.operands);
        j.set_u("length", insn.length);
        if (insn.has_target) j.set_hex("target", insn.target);
        if (!note_label.empty()) j.set_str("label", note_label);
        if (!note_text.empty()) j.set_str("note", note_text);
        if (!comment.empty()) j.set_str("comment", comment);
        arr.push(std::move(j));

        t += fmt("%s  %-24s %-32s%s\n", hex8(cur).c_str(), bytes_to_hex(insn.bytes).c_str(),
                 insn.text.c_str(), comment.empty() ? "" : ("; " + comment).c_str());
        off += insn.length;
        cur += insn.length;
        ++i;
    }
    Json d = Json::obj();
    d.set_hex("start", addr);
    d.set_str("arch", e.arch_text());
    d.set("instructions", arr);
    return ok(d, t);
}

CmdResult cmd_modules(Engine& e, CliConfig&, const std::vector<std::string>&) {
    Json arr = Json::arr();
    std::string t = fmt("%-18s %-18s %-12s %-24s %s\n", "base", "image_base", "slide", "name",
                        "path");
    t += std::string(96, '-') + "\n";
    for (auto& m : e.modules()) {
        Json j = Json::obj();
        j.set_hex("base", m.base);
        j.set_u("size", m.size);
        j.set_str("name", m.name);
        j.set_str("path", m.path);
        if (m.preferred_base) {
            j.set_hex("image_base", m.preferred_base);
            j.set_bool("relocated", m.relocated());
            if (m.relocated()) j.set_hex("slide", m.slide());
        }
        arr.push(std::move(j));
        t += fmt("%-18s %-18s %-12s %-24s %s\n", hex8(m.base).c_str(),
                 m.preferred_base ? hex8(m.preferred_base).c_str() : "-",
                 m.relocated() ? hex8(m.slide()).c_str() : (m.preferred_base ? "0" : "-"),
                 m.name.c_str(), m.path.c_str());
    }
    Json d = Json::obj();
    d.set("modules", arr);
    d.set_u("count", e.modules().size());
    return ok(d, t);
}

CmdResult cmd_threads(Engine& e, CliConfig&, const std::vector<std::string>&) {
    Json arr = Json::arr();
    std::string t = fmt("%-8s %-18s %-18s %s\n", "tid", "start", "rip", "current");
    t += std::string(56, '-') + "\n";
    for (auto& th : e.threads()) {
        if (!th.alive) continue;
        uint64_t rip = 0;
        if (th.handle) {
            CpuState st;
            std::string e2;
            if (aj::get_state(th.handle, e.is32(), st, e2)) rip = st.rip;
        }
        Json j = Json::obj();
        j.set_u("tid", th.tid);
        j.set_hex("start", th.entry);
        j.set_hex("rip", rip);
        j.set_bool("current", th.tid == e.tid());
        arr.push(std::move(j));
        t += fmt("%-8u %-18s %-18s %s\n", th.tid, hex8(th.entry).c_str(), hex8(rip).c_str(),
                 th.tid == e.tid() ? "*" : "");
    }
    Json d = Json::obj();
    d.set("threads", arr);
    return ok(d, t);
}

CmdResult cmd_thread(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "thread <tid>"))
        return fail("bad_args", "thread <tid>");
    uint64_t tid = 0;
    if (!parse_u64(a[0], tid)) return fail("bad_args", "invalid tid");
    bool found = false;
    for (auto& th : e.threads())
        if (th.tid == (uint32_t)tid && th.alive) found = true;
    if (!found) return fail("not_found", "no such thread");
    e.set_tid((uint32_t)tid);
    Json d = Json::obj();
    d.set_u("tid", tid);
    return ok(d, fmt("current thread is now %llu\n", (unsigned long long)tid));
}

CmdResult cmd_processes(Engine& e, CliConfig&, const std::vector<std::string>&) {
    Json arr = Json::arr();
    std::string t = fmt("%-8s %-6s %-9s %-22s %-12s %s\n", "pid", "arch", "state", "name", "mod/thr", "");
    t += std::string(72, '-') + "\n";
    for (auto& p : e.processes()) {
        bool cur = (p.pid == e.pid());
        Json j = Json::obj();
        j.set_u("pid", p.pid);
        j.set_str("arch", p.arch_text());
        j.set_bool("alive", p.alive);
        j.set_str("name", p.exe_name);
        j.set_str("path", p.exe_path);
        j.set_u("modules", p.modules.size());
        j.set_u("threads", p.threads.size());
        j.set_bool("current", cur);
        arr.push(std::move(j));
        t += fmt("%-8u %-6s %-9s %-22s %-12s %s\n", p.pid, p.arch_text(),
                 p.alive ? "alive" : "exited", p.exe_name.c_str(),
                 fmt("%zu/%zu", p.modules.size(), p.threads.size()).c_str(),
                 cur ? "<- current" : "");
    }
    Json d = Json::obj();
    d.set("processes", arr);
    d.set_u("count", e.processes().size());
    return ok(d, t);
}

CmdResult cmd_process(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "process <pid>")) return fail("bad_args", "process <pid>");
    uint64_t pid = 0;
    if (!parse_u64(a[0], pid)) return fail("bad_args", "invalid pid");
    std::string err;
    if (!e.set_current_process((uint32_t)pid, err)) return fail("switch_failed", err);
    Json d = Json::obj();
    d.set_u("pid", pid);
    d.set_str("arch", e.arch_text());
    d.set_u("modules", e.modules().size());
    d.set_u("threads", e.threads().size());
    return ok(d, fmt("current process is now %llu (%s)\n", (unsigned long long)pid,
                     e.arch_text()));
}

CmdResult cmd_stack(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    uint64_t max = 32;
    if (!a.empty() && !parse_u64(a[0], max)) return fail("bad_args", "invalid frame count");
    if (max == 0 || max > 256) max = 32;
    Json frames = e.callstack((size_t)max);
    Json d = Json::obj();
    d.set("frames", frames);

    std::string t = fmt("%-4s %-18s %-34s %s\n", "#", "address", "symbol", "source");
    t += std::string(78, '-') + "\n";
    for (size_t i = 0; i < frames.size(); ++i) {
        const Json& f = frames.at(i);
        std::string sym = f.get("symbol").as_str();
        uint64_t disp = f.get("symbol_disp").as_u();
        if (!sym.empty() && disp) sym += fmt("+0x%llx", (unsigned long long)disp);
        if (sym.empty()) {
            std::string mod = f.get("module").as_str();
            if (!mod.empty())
                sym = fmt("%s+0x%llx", mod.c_str(),
                          (unsigned long long)f.get("module_offset").as_u());
        }
        std::string src;
        if (!f.get("file").as_str().empty())
            src = fmt("%s:%llu", f.get("file").as_str().c_str(),
                      (unsigned long long)f.get("line").as_u());
        t += fmt("%-4llu %-18s %-34s %s\n", (unsigned long long)i,
                 f.get("address").as_str("-").c_str(), sym.c_str(), src.c_str());
    }
    return ok(d, t);
}

CmdResult cmd_symbols(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    std::string mask = a.empty() ? "*" : a[0];
    uint64_t max = 64;
    if (a.size() > 1 && !parse_u64(a[1], max)) return fail("bad_args", "invalid max");
    if (max > 2000) max = 2000;
    Json arr = e.sym.enumerate(mask, (size_t)max);
    Json d = Json::obj();
    d.set("symbols", arr);
    d.set_u("count", arr.size());

    std::string t = fmt("%zu symbol(s) matching '%s'\n", arr.size(), mask.c_str());
    t += fmt("%-18s %-10s %s\n", "address", "size", "name");
    t += std::string(50, '-') + "\n";
    for (size_t i = 0; i < arr.size(); ++i) {
        const Json& s = arr.at(i);
        t += fmt("%-18s %-10s %s\n", s.get("address").as_str("-").c_str(),
                 fmt("0x%llx", (unsigned long long)s.get("size").as_u()).c_str(),
                 s.get("name").as_str().c_str());
    }
    return ok(d, t);
}

CmdResult cmd_eval(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "eval <expression>"))
        return fail("bad_args", "eval <expression>");
    std::string expr = join_from(a, 0);
    uint64_t v = 0;
    std::string err;
    if (!e.eval(expr, v, err)) return fail("eval_failed", err);
    Json d = Json::obj();
    d.set_str("expression", expr);
    d.set_hex("value", v);
    d.set_u("value_dec", v);
    const ModuleInfo* m = e.module_at(v);
    if (m) {
        d.set_str("module", m->name);
        d.set_hex("module_offset", v - m->base);
    }
    std::string sym;
    uint64_t disp = 0;
    if (e.sym.lookup_address(v, sym, disp, err)) {
        d.set_str("symbol", sym);
        if (disp) d.set_hex("symbol_disp", disp);
    }
    return ok(d, fmt("%s = %s (%llu)\n", expr.c_str(), hex8(v).c_str(),
                     (unsigned long long)v));
}

// ------------------------------------------------------------- exceptions

CmdResult cmd_exlist(Engine& e, CliConfig&, const std::vector<std::string>&) {
    Json d = e.policy.to_json();
    return ok(d, e.policy.to_text());
}

CmdResult cmd_exset(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 2, "exset <code> <break|ignore|pass>"))
        return fail("bad_args", "exset <code> <break|ignore|pass>");
    uint64_t code = 0;
    std::string cs = a[0];
    // allow names like AV / bp / ss
    std::string cl = to_lower(cs);
    if (cl == "av") code = 0xC0000005;
    else if (cl == "bp") code = 0x80000003;
    else if (cl == "ss") code = 0x80000004;
    else if (cl == "guard") code = 0x80000001;
    else if (cl == "cpp") code = 0xE06D7363;
    else if (!parse_u64(cs, code)) return fail("bad_args", "invalid exception code");
    ExAction act;
    if (!ExceptionPolicy::parse_action(a[1], act))
        return fail("bad_args", "action must be break, ignore or pass");
    e.policy.set((uint32_t)code, act);
    Json d = Json::obj();
    d.set_str("code", fmt("0x%08X", (uint32_t)code));
    d.set_str("name", ExceptionPolicy::name_of((uint32_t)code));
    d.set_str("action", ExceptionPolicy::action_text(act));
    return ok(d, fmt("%s (0x%08X) -> %s\n", ExceptionPolicy::name_of((uint32_t)code).c_str(),
                     (uint32_t)code, ExceptionPolicy::action_text(act).c_str()));
}

CmdResult cmd_exdel(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "exdel <code>"))
        return fail("bad_args", "exdel <code>");
    uint64_t code = 0;
    if (!parse_u64(a[0], code)) return fail("bad_args", "invalid exception code");
    bool r = e.policy.remove((uint32_t)code);
    Json d = Json::obj();
    d.set_bool("removed", r);
    return ok(d, r ? "rule removed\n" : "no such rule\n");
}

CmdResult cmd_exall(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "exall <on|off>"))
        return fail("bad_args", "exall <on|off>");
    std::string v = to_lower(a[0]);
    if (v != "on" && v != "off") return fail("bad_args", "exall <on|off>");
    e.policy.ignore_all = (v == "on");
    Json d = Json::obj();
    d.set_bool("ignore_all", e.policy.ignore_all);
    return ok(d, fmt("ignore_all = %s\n", v.c_str()));
}

// ------------------------------------------------------------------- types

CmdResult cmd_ptype(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "ptype <type>")) return fail("bad_args", "ptype <type>");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    std::string name = join_from(a, 0);
    e.types.init(e.process());
    TypeInfo t;
    std::string err;
    // UDTs are often only findable when the lookup is scoped to a module, so
    // try every loaded module before giving up.
    bool found = e.types.by_name(name, t, err);
    if (!found) {
        for (auto& m : e.modules()) {
            if (e.types.by_name(name, t, err, m.base)) {
                found = true;
                break;
            }
        }
    }
    if (!found) return fail("unknown_type", err);

    Json d = e.types.describe(t);
    d.set_str("name", name);

    std::string text = fmt("%s  (size 0x%llx = %llu bytes)\n", e.types.name_of(t).c_str(),
                           (unsigned long long)t.length, (unsigned long long)t.length);
    auto fields = e.types.fields(t);
    if (fields.empty()) {
        text += "  (no data members)\n";
    } else {
        text += fmt("%-10s %-24s %s\n", "offset", "type", "name");
        text += std::string(58, '-') + "\n";
        for (auto& f : fields) {
            text += fmt("+0x%-8llx %-24s %s\n", (unsigned long long)f.offset,
                        f.type_name.c_str(), f.name.c_str());
        }
    }
    return ok(d, text);
}

CmdResult cmd_whatis(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "whatis <symbol|expression>"))
        return fail("bad_args", "whatis <symbol|expression>");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    std::string name = join_from(a, 0);
    e.types.init(e.process());

    // a plain symbol first, then any expression such as `list.head->value`
    TypeInfo t;
    std::string err;
    if (e.types.by_symbol(name, t, err)) {
        std::string tn = e.types.name_of(t);
        Json d = Json::obj();
        d.set_str("expression", name);
        d.set_str("type", tn);
        d.set_u("size", t.length);
        return ok(d, fmt("%s: %s  (size %llu)\n", name.c_str(), tn.c_str(),
                         (unsigned long long)t.length));
    }

    TypedValue tv;
    if (!e.typed_eval(name, tv, err)) return fail("no_type", err);
    if (tv.type_name.empty()) return fail("no_type", "no type information for: " + name);
    Json d = Json::obj();
    d.set_str("expression", name);
    d.set_str("type", tv.type_name);
    d.set_u("size", tv.type.length);
    d.set_hex("address", tv.address);
    return ok(d, fmt("%s: %s  (size %llu, at %s)\n", name.c_str(), tv.type_name.c_str(),
                     (unsigned long long)tv.type.length, hex8(tv.address).c_str()));
}

CmdResult cmd_print(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "print <expression>"))
        return fail("bad_args", "print <expression>");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    std::string expr = join_from(a, 0);
    TypedValue tv;
    std::string err;
    if (!e.typed_eval(expr, tv, err)) return fail("eval_failed", err);

    Json d = Json::obj();
    d.set_str("expression", expr);
    if (!tv.type_name.empty()) d.set_str("type", tv.type_name);
    d.set_hex("address", tv.address);
    d.set_str("value", tv.display);

    std::string text = fmt("%s = %s", expr.c_str(), tv.display.c_str());
    if (!tv.type_name.empty())
        text += fmt("   <%s> @ %s", tv.type_name.c_str(), hex8(tv.address).c_str());
    text += "\n";

    // aggregates get a field-by-field dump so nothing has to be guessed
    if (tv.type.valid && e.types.is_udt(tv.type)) {
        Json layout = e.types.describe(tv.type);
        d.set("layout", layout);
        auto fields = e.types.fields(tv.type);
        for (auto& f : fields) {
            if (f.offset + (f.type.length ? f.type.length : 1) > 512) continue;
            TypedValue fv;
            std::string fe;
            if (!e.typed_eval(expr + "." + f.name, fv, fe)) continue;
            text += fmt("  +0x%-6llx %-22s %-20s %s\n", (unsigned long long)f.offset,
                        f.type_name.c_str(), f.name.c_str(), fv.display.c_str());
        }
    }
    return ok(d, text);
}

// ------------------------------------------------------------- tracing

// `stepuntil <cond...> [max=N]` and friends: the condition may contain spaces,
// so everything is the condition except an optional trailing `max=N` (or a bare
// number, which cannot be a meaningful condition on its own).
bool split_cond_args(const std::vector<std::string>& a, std::string& cond, uint64_t& max,
                     std::string& err) {
    std::vector<std::string> parts = a;
    max = 0;
    bool max_set = false;
    if (!parts.empty()) {
        const std::string& last = parts.back();
        if (starts_with(last, "max=") || starts_with(last, "max:")) {
            if (!parse_u64(last.substr(4), max)) {
                err = "invalid max";
                return false;
            }
            parts.pop_back();
            max_set = true;
        }
    }
    // A bare trailing number is only read as `max` when max was not given
    // explicitly; otherwise `stepuntil eax == 3 max=200` would eat the "3".
    if (!max_set && parts.size() >= 2) {
        uint64_t v = 0;
        if (parse_u64(parts.back(), v)) {
            max = v;
            parts.pop_back();
        }
    }
    if (parts.empty()) {
        err = "missing condition";
        return false;
    }
    cond.clear();
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) cond += ' ';
        cond += parts[i];
    }
    return true;
}

// Evaluates the condition in the target's current state.
bool cond_true(Engine& e, const std::string& cond, uint64_t& value, std::string& err) {
    if (!e.eval(cond, value, err)) return false;
    return value != 0;
}

CmdResult cmd_stepuntil(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "stepuntil <condition> [max_steps]"))
        return fail("bad_args", "stepuntil <condition> [max_steps]");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    std::string cond;
    uint64_t max = 0;
    std::string err;
    if (!split_cond_args(a, cond, max, err)) return fail("bad_args", err);
    if (max == 0) max = 10000;
    if (max > 1000000) max = 1000000;

    // stepping a thousand times must not create a thousand memory snapshots
    bool prev_auto = e.snaps.auto_enabled();
    e.snaps.set_auto(false);

    uint64_t steps = 0;
    uint64_t value = 0;
    std::string eval_err;
    while (steps < max) {
        if (!e.resume(ResumeAction::StepInto, 0, 0, err)) {
            e.snaps.set_auto(prev_auto);
            return fail("step_failed", err);
        }
        ++steps;
        if (e.stop_info().reason == StopReason::Exit) break;
        if (cond_true(e, cond, value, eval_err)) {
            e.snaps.set_auto(prev_auto);
            Json d = Json::obj();
            d.set_str("condition", cond);
            d.set_u("steps", steps);
            // the condition's own value: 1 = true. Use `regs`/`eval` for the
            // underlying registers or memory.
            d.set_u("condition_value", value);
            d.set_bool("condition_met", true);
            d.set_str("rip", e.session_meta().rip);
            return ok(d, fmt("condition '%s' true after %llu step(s)\n", cond.c_str(),
                             (unsigned long long)steps));
        }
    }
    e.snaps.set_auto(prev_auto);
    return fail("condition_not_met",
                fmt("'%s' still false after %llu step(s)", cond.c_str(),
                    (unsigned long long)steps));
}

CmdResult cmd_rununtil(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "rununtil <condition> [max_cycles]"))
        return fail("bad_args", "rununtil <condition> [max_cycles]");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    std::string cond;
    uint64_t max = 0;
    std::string err;
    if (!split_cond_args(a, cond, max, err)) return fail("bad_args", err);
    if (max == 0) max = 1000;
    if (max > 100000) max = 100000;

    bool prev_auto = e.snaps.auto_enabled();
    e.snaps.set_auto(false);

    uint64_t cycles = 0;
    uint64_t value = 0;
    std::string eval_err;
    while (cycles < max) {
        // bounded per cycle so a runaway target cannot hang the caller
        if (!e.resume(ResumeAction::Continue, 0, 10000, err)) {
            e.snaps.set_auto(prev_auto);
            return fail("resume_failed", err);
        }
        ++cycles;
        if (e.stop_info().reason == StopReason::Exit) break;
        if (cond_true(e, cond, value, eval_err)) {
            e.snaps.set_auto(prev_auto);
            Json d = Json::obj();
            d.set_str("condition", cond);
            d.set_u("cycles", cycles);
            d.set_u("condition_value", value);
            d.set_bool("condition_met", true);
            d.set("stop", e.stop_info().to_json());
            return ok(d, fmt("condition '%s' true after %llu stop(s)\n", cond.c_str(),
                             (unsigned long long)cycles));
        }
    }
    e.snaps.set_auto(prev_auto);
    return fail("condition_not_met",
                fmt("'%s' still false after %llu stop(s)", cond.c_str(),
                    (unsigned long long)cycles));
}

CmdResult cmd_autostep(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "autostep <count> [delay_ms]"))
        return fail("bad_args", "autostep <count> [delay_ms]");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    uint64_t count = 0;
    if (!parse_u64(a[0], count)) return fail("bad_args", "invalid count");
    if (count == 0) count = 1;
    if (count > 1000) return fail("bad_args", "count too large (max 1000)");
    uint64_t delay = 0;
    if (a.size() > 1 && !parse_u64(a[1], delay)) return fail("bad_args", "invalid delay");

    bool prev_auto = e.snaps.auto_enabled();
    e.snaps.set_auto(false);

    Json trace = Json::arr();
    std::string text;
    std::string err;
    for (uint64_t i = 0; i < count; ++i) {
        // record where we are, then step
        CpuState st;
        if (!e.get_state(st, err)) break;
        uint8_t buf[16] = {0};
        std::string e2;
        read_memory(e.process(), st.rip, buf, sizeof(buf), e2);
        Insn insn;
        decode_one(buf, sizeof(buf), st.rip, insn, e.is32());

        Json ij = Json::obj();
        ij.set_u("index", i);
        ij.set_hex("address", st.rip);
        ij.set_str("bytes", bytes_to_hex(insn.bytes));
        ij.set_str("text", insn.text);
        trace.push(std::move(ij));
        text += fmt("[%4llu] %s  %-24s %s\n", (unsigned long long)i, hex8(st.rip).c_str(),
                    bytes_to_hex(insn.bytes).c_str(), insn.text.c_str());

        if (!e.resume(ResumeAction::StepInto, 0, 0, err)) break;
        if (e.stop_info().reason == StopReason::Exit) break;
        if (delay) Sleep((DWORD)delay);
    }
    e.snaps.set_auto(prev_auto);

    Json d = Json::obj();
    d.set_u("count", trace.size());
    d.set("trace", trace);
    return ok(d, text);
}

// ---------------------------------------------------------- control flow

CmdResult cmd_flow(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    uint64_t addr = 0;
    if (a.empty()) {
        if (!e.is_paused())
            return fail("not_paused", "target is not paused (specify an address)");
        CpuState st;
        std::string err;
        if (!e.get_state(st, err)) return fail("cfg_failed", err);
        addr = st.rip;
    } else {
        CmdResult dummy;
        if (!resolve(e, a[0], addr, dummy)) return dummy;
    }
    uint64_t max_blocks = 64;
    if (a.size() > 1 && !parse_u64(a[1], max_blocks))
        return fail("bad_args", "invalid block count");
    if (max_blocks == 0 || max_blocks > 512) max_blocks = 64;

    CfgInput in;
    in.is32 = e.is32();
    in.read = [&e](uint64_t a2, void* buf, size_t n, std::string& err) {
        size_t got = 0;
        return read_memory(e.process(), a2, buf, n, err, &got) && got == n;
    };
    in.extent = [&e](uint64_t a2, uint64_t& s, uint64_t& en, std::string& name) {
        return e.sym.function_extent(a2, s, en, name);
    };
    in.annotate = [&e](uint64_t a2) {
        std::string name;
        uint64_t disp = 0;
        std::string err;
        if (!e.sym.lookup_address(a2, name, disp, err)) return std::string();
        return disp ? fmt("%s+0x%llx", name.c_str(), (unsigned long long)disp) : name;
    };

    Cfg c;
    std::string err;
    if (!build_cfg(in, addr, (size_t)max_blocks, c, err)) return fail("cfg_failed", err);
    Json d = cfg_to_json(c);
    d.set_str("arch", e.arch_text());
    return ok(d, cfg_to_text(c, true));
}

// ------------------------------------------------------- snapshots / reverse

CmdResult cmd_snapshot(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    std::string action = a.empty() ? "list" : to_lower(a[0]);
    std::string arg = a.size() > 1 ? join_from(a, 1) : std::string();
    std::string err;

    if (action == "save") {
        if (!e.snapshot_save(arg, err)) return fail("snapshot_failed", err);
        Json d = Json::obj();
        d.set_str("name", arg);
        d.set_u("count", e.snaps.count());
        d.set_u("stored_bytes", e.snaps.stored_bytes());
        return ok(d, fmt("snapshot saved (%zu total, %zu KB stored)\n", e.snaps.count(),
                         e.snaps.stored_bytes() / 1024));
    }
    if (action == "restore") {
        if (!e.snapshot_restore(arg, err)) return fail("restore_failed", err);
        Json d = Json::obj();
        d.set_str("rip", e.session_meta().rip);
        d.set_u("snapshots", e.snaps.count());
        return ok(d, fmt("restored snapshot%s\n", arg.empty() ? "" : (" " + arg).c_str()));
    }
    if (action == "delete" || action == "del") {
        size_t idx = 0;
        if (!e.snaps.find(arg, idx)) return fail("not_found", "no such snapshot: " + arg);
        e.snaps.remove(idx);
        Json d = Json::obj();
        d.set_u("remaining", e.snaps.count());
        return ok(d, fmt("snapshot %s removed (%zu left)\n", arg.c_str(), e.snaps.count()));
    }
    if (action == "clear") {
        e.snaps.clear();
        Json d = Json::obj();
        d.set_u("removed", (uint64_t)0);
        return ok(d, "all snapshots cleared\n");
    }
    if (action == "auto") {
        std::string v = to_lower(arg);
        if (v != "on" && v != "off") return fail("bad_args", "snapshot auto <on|off>");
        e.snaps.set_auto(v == "on");
        Json d = Json::obj();
        d.set_bool("auto", e.snaps.auto_enabled());
        return ok(d, fmt("auto capture %s\n", v.c_str()));
    }
    if (action == "file") {
        if (arg.empty()) {
            Json d = Json::obj();
            d.set_str("path", e.snaps.store_path());
            d.set_bool("open", e.snaps.store_open());
            return ok(d, e.snaps.store_open()
                            ? ("store: " + e.snaps.store_path() + "\n")
                            : "no snapshot store open\n");
        }
        if (!e.snaps.open_store(arg, err)) return fail("store_failed", err);
        Json d = Json::obj();
        d.set_str("path", e.snaps.store_path());
        d.set_u("records", e.snaps.store().count());
        return ok(d, fmt("snapshot store: %s (%zu records)\n", e.snaps.store_path().c_str(),
                         e.snaps.store().count()));
    }
    if (action == "history") {
        if (!e.snaps.store_open()) return fail("no_store", "no snapshot store open (use: snapshot file <path>)");
        Json arr = Json::arr();
        std::string t = fmt("%-6s %-6s %-8s %-6s %-18s %-10s %-10s %s\n", "id", "kind", "prev",
                            "arch", "rip", "raw", "stored", "name");
        t += std::string(88, '-') + "\n";
        for (const auto& r : e.snaps.store().records()) {
            if (r.deleted) continue;
            Json j = Json::obj();
            j.set_u("id", r.id);
            j.set_str("kind", r.is_full() ? "full" : "delta");
            if (r.prev_id != 0xFFFFFFFFu) j.set_u("prev_id", r.prev_id);
            j.set_u("pid", r.pid);
            j.set_str("arch", r.is32 ? "x86" : "x64");
            j.set_hex("rip", r.regs.rip);
            j.set_str("name", r.name);
            j.set_str("stop_reason", r.stop_reason);
            j.set_u("raw_bytes", r.raw_size);
            j.set_u("stored_bytes", r.stored_size);
            j.set_u("timestamp", r.timestamp);
            arr.push(std::move(j));
            t += fmt("%-6u %-6s %-8s %-6s %-18s %-10s %-10s %s\n", r.id,
                     r.is_full() ? "full" : "delta",
                     r.prev_id == 0xFFFFFFFFu ? "-" : std::to_string(r.prev_id).c_str(),
                     r.is32 ? "x86" : "x64", hex8(r.regs.rip).c_str(),
                     fmt("%zu KB", (size_t)(r.raw_size / 1024)).c_str(),
                     fmt("%zu KB", (size_t)(r.stored_size / 1024)).c_str(), r.name.c_str());
        }
        Json d = Json::obj();
        d.set("records", arr);
        d.set_u("count", arr.size());
        d.set_str("path", e.snaps.store_path());
        d.set_u("file_bytes", e.snaps.store().file_size());
        d.set_u("dead_bytes", e.snaps.store().dead_bytes());
        return ok(d, t);
    }
    if (action == "load") {
        uint64_t id = 0;
        if (arg.empty() || !parse_u64(arg, id))
            return fail("bad_args", "snapshot load <id>");
        if (!e.is_paused()) return fail("not_paused", "target is not paused");
        if (!e.snaps.restore_from_store((uint32_t)id, e.process(), e.thread(), err))
            return fail("restore_failed", err);
        Json d = Json::obj();
        d.set_u("id", id);
        d.set_u("skipped_pages", e.snaps.skipped_pages());
        return ok(d, fmt("restored snapshot %llu from the store (skipped %zu un-writable page(s))\n",
                         (unsigned long long)id, e.snaps.skipped_pages()));
    }
    if (action == "compact") {
        if (!e.snaps.store_open()) return fail("no_store", "no snapshot store open");
        uint64_t reclaimed = 0;
        if (!e.snaps.compact_store(reclaimed, err)) return fail("store_failed", err);
        Json d = Json::obj();
        d.set_u("reclaimed_bytes", reclaimed);
        d.set_u("file_bytes", e.snaps.store().file_size());
        return ok(d, fmt("compacted, reclaimed %llu bytes (file is now %llu bytes)\n",
                         (unsigned long long)reclaimed,
                         (unsigned long long)e.snaps.store().file_size()));
    }
    if (action == "list" || action == "ls") {
        Json d = e.snaps.to_json();
        if (e.snaps.store_open()) {
            d.set_str("store_path", e.snaps.store_path());
            d.set_u("store_records", e.snaps.store().count());
            d.set_u("store_file_bytes", e.snaps.store().file_size());
        }
        return ok(d, e.snaps.to_text());
    }
    return fail("bad_args",
                "usage: snapshot [save [name] | restore [name|index] | list | "
                "delete <name|index> | clear | auto <on|off> | file [path] | "
                "history | load <id> | compact]");
}

CmdResult cmd_stepback(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    uint64_t n = 1;
    if (!a.empty() && !parse_u64(a[0], n)) return fail("bad_args", "invalid count");
    if (n == 0) n = 1;
    size_t count = e.snaps.count();
    if (count < 2) return fail("no_history", "no earlier snapshot to go back to");
    if (n >= count) n = count - 1;
    size_t target = count - 1 - (size_t)n;

    std::string err;
    if (!e.snapshot_restore(std::to_string(target), err)) return fail("restore_failed", err);
    // drop everything newer so a repeated stepback keeps walking backwards
    while (e.snaps.count() > target + 1) e.snaps.remove(e.snaps.count() - 1);

    Json d = Json::obj();
    d.set_u("index", (uint64_t)target);
    d.set_u("remaining", e.snaps.count());
    return ok(d, fmt("stepped back to snapshot %zu (%zu left)\n", target, e.snaps.count()));
}

// ----------------------------------------------------------- TEB/PEB/heap/handles

CmdResult cmd_teb(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    HANDLE thread = e.thread();
    if (!a.empty()) {
        uint64_t tid = 0;
        if (!parse_u64(a[0], tid)) return fail("bad_args", "invalid tid");
        for (auto& t : e.threads())
            if (t.tid == (uint32_t)tid && t.handle) thread = t.handle;
        if (!thread) return fail("not_found", "no such thread");
    }
    PebInfo pb;
    std::string perr;
    bool have_peb = read_peb(e.process(), e.is32(), pb, perr);

    TebInfo t;
    std::string err;
    if (!read_teb(e.process(), thread, e.is32(), t, err, have_peb ? pb.address : 0))
        return fail("teb_failed", err);
    Json d = teb_to_json(t);
    d.set("teb", teb_to_json(t));
    std::string txt = fmt("TEB %s  (%s)\n", hex8(t.address).c_str(), e.arch_text());
    txt += fmt("  pid/tid            %llu / %llu\n", (unsigned long long)t.pid,
               (unsigned long long)t.tid);
    txt += fmt("  PEB                %s\n", hex8(t.peb).c_str());
    if (have_peb && t.peb != pb.address)
        txt += fmt("  [!] differs from the validated PEB %s\n", hex8(pb.address).c_str());
    txt += fmt("  stack base         %s\n", hex8(t.stack_base).c_str());
    txt += fmt("  stack limit        %s\n", hex8(t.stack_limit).c_str());
    txt += fmt("  stack size         %llu\n",
               (unsigned long long)(t.stack_base > t.stack_limit ? t.stack_base - t.stack_limit : 0));
    txt += fmt("  deallocation stack %s\n", hex8(t.deallocation_stack).c_str());
    txt += fmt("  last error         %llu\n", (unsigned long long)t.last_error);
    return ok(d, txt);
}

CmdResult cmd_peb(Engine& e, CliConfig&, const std::vector<std::string>&) {
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    PebInfo p;
    std::string err;
    if (!read_peb(e.process(), e.is32(), p, err)) return fail("peb_failed", err);
    Json d = peb_to_json(p);

    // self-check: the PEB's ImageBaseAddress must be the main module's base
    std::string note;
    if (!e.modules().empty()) {
        if (p.image_base == e.modules().front().base) {
            note = "  [ok] ImageBaseAddress matches the main module base\n";
        } else {
            note = fmt("  [!] ImageBaseAddress %s != main module base %s\n",
                       hex8(p.image_base).c_str(), hex8(e.modules().front().base).c_str());
        }
    }

    std::string txt = fmt("PEB %s  (%s)\n", hex8(p.address).c_str(), e.arch_text());
    txt += fmt("  BeingDebugged      %u\n", p.being_debugged);
    txt += fmt("  ImageBaseAddress   %s\n", hex8(p.image_base).c_str());
    txt += fmt("  Ldr                %s\n", hex8(p.ldr).c_str());
    txt += fmt("  ProcessParameters  %s\n", hex8(p.process_parameters).c_str());
    txt += fmt("  ProcessHeap        %s\n", hex8(p.process_heap).c_str());
    txt += fmt("  NtGlobalFlag       0x%X%s\n", p.nt_global_flag,
               (p.nt_global_flag & 0x70) ? "  [debugger flags set]" : "");
    txt += fmt("  NumberOfProcessors %u\n", p.number_of_processors);
    txt += fmt("  SessionId          %u\n", p.session_id);
    txt += note;
    return ok(d, txt);
}

CmdResult cmd_heap(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.active()) return fail("no_target", "no active target");
    uint64_t max_blocks = 20;
    if (!a.empty() && !parse_u64(a[0], max_blocks)) return fail("bad_args", "invalid count");
    if (max_blocks > 2000) max_blocks = 2000;

    std::vector<HeapInfo> heaps;
    std::string err;
    if (!enum_heaps(e.pid(), heaps, (size_t)max_blocks, err))
        return fail("heap_failed", err);

    Json arr = Json::arr();
    std::string t = fmt("%-20s %-10s %-12s %s\n", "heap id", "blocks", "total", "largest block");
    t += std::string(64, '-') + "\n";
    for (auto& h : heaps) {
        uint64_t biggest = 0;
        for (auto& b : h.blocks)
            if (b.size > biggest) biggest = b.size;
        Json j = Json::obj();
        j.set_hex("id", h.id);
        j.set_u("blocks", h.block_count);
        j.set_u("total_bytes", h.total_bytes);
        j.set_u("largest_block", biggest);
        arr.push(std::move(j));
        t += fmt("%-20s %-10zu %-12llu %llu\n", hex8(h.id).c_str(), h.block_count,
                 (unsigned long long)h.total_bytes, (unsigned long long)biggest);
    }
    Json d = Json::obj();
    d.set("heaps", arr);
    d.set_u("count", heaps.size());
    return ok(d, t);
}

CmdResult cmd_handles(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.active()) return fail("no_target", "no active target");
    std::string type_filter = a.empty() ? "" : to_lower(a[0]);
    uint64_t max = 100;
    if (a.size() > 1 && !parse_u64(a[1], max)) return fail("bad_args", "invalid max");
    if (max > 5000) max = 5000;

    std::vector<HandleInfo> list;
    std::string err;
    if (!enum_handles(e.pid(), type_filter, list, (size_t)max, err))
        return fail("handles_failed", err);

    Json arr = Json::arr();
    std::string t = fmt("%-12s %-22s %-10s %s\n", "handle", "type", "access", "name");
    t += std::string(84, '-') + "\n";
    for (auto& h : list) {
        Json j = Json::obj();
        j.set_hex("value", h.value);
        j.set_str("type", h.type);
        j.set_str("name", h.name);
        j.set_u("access", h.access);
        arr.push(std::move(j));
        t += fmt("0x%-10llX %-22s 0x%-8X %s\n", (unsigned long long)h.value, h.type.c_str(),
                 h.access, h.name.c_str());
    }
    Json d = Json::obj();
    d.set("handles", arr);
    d.set_u("count", list.size());
    return ok(d, list.empty() ? "no matching handles\n" : t);
}

// ------------------------------------------------------------------- dump

CmdResult cmd_dump(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "dump <file> [addr] [entry=<addr>] [compact] [keepbase]"))
        return fail("bad_args", "dump <file> [addr] [entry=<addr>] [compact] [keepbase]");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");

    std::string path = a[0];
    uint64_t base = 0;
    size_t idx = 1;
    if (idx < a.size() && a[idx].find('=') == std::string::npos && a[idx] != "compact" &&
        a[idx] != "keepbase") {
        CmdResult dummy;
        if (!resolve(e, a[idx], base, dummy)) return dummy;
        ++idx;
    }
    if (!base) {
        if (e.modules().empty()) return fail("no_target", "no modules loaded");
        base = e.modules().front().base;
    }

    DumpOptions opts;
    for (; idx < a.size(); ++idx) {
        const std::string& t = a[idx];
        if (t == "compact") {
            opts.compact = true;
        } else if (t == "keepbase") {
            opts.pin_image_base = false;
        } else if (starts_with(t, "entry=")) {
            CmdResult dummy;
            if (!resolve(e, t.substr(6), opts.entry_point, dummy))
                return fail("bad_args", "bad entry address");
        } else {
            return fail("bad_args", "unknown option: " + t);
        }
    }

    Json report;
    std::string err;
    if (!dump_pe(e.process(), base, path, opts, report, err))
        return fail("dump_failed", err);

    std::string t = fmt("dumped %s\n", path.c_str());
    t += fmt("  base           %s\n", hex8(base).c_str());
    t += fmt("  file size      %llu bytes\n", (unsigned long long)report.get("file_size").as_u());
    t += fmt("  size of image  %llu\n", (unsigned long long)report.get("size_of_image").as_u());
    t += fmt("  sections       %llu\n", (unsigned long long)report.get("sections").as_u());
    if (opts.entry_point) t += fmt("  entry point    %s\n", hex8(opts.entry_point).c_str());
    t += fmt("  image base     %s\n", opts.pin_image_base ? "pinned to the load address"
                                                          : "left as in the original");
    return ok(report, t);
}

// ------------------------------------------- import table / export resolution

// Caches parsed export tables while walking an IAT, so a large import region
// does not re-parse the same module over and over.
struct ExportCache {
    Engine& e;
    std::map<uint64_t, Exports> by_base;

    Exports& get(uint64_t base, const std::string& name) {
        auto it = by_base.find(base);
        if (it != by_base.end()) return it->second;
        Exports ex;
        ex.init(e.process(), base, name);
        std::string err;
        ex.load(err);
        return by_base.emplace(base, std::move(ex)).first->second;
    }
};

// Resolves one pointer value to `module!function`, following import thunks.
bool resolve_import_slot(Engine& e, ExportCache& cache, uint64_t value, std::string& module,
                         std::string& function, uint64_t& ordinal, std::string& forwarder) {
    module.clear();
    function.clear();
    forwarder.clear();
    ordinal = 0;
    if (!value) return false;

    uint64_t addr = value;
    follow_thunk(e.process(), addr, addr);

    const ModuleInfo* m = e.module_at(addr);
    if (!m) return false;
    module = m->name;

    Exports& ex = cache.get(m->base, m->name);
    ExportEntry ent;
    if (ex.find_by_address(addr, ent)) {
        function = ent.name.empty() ? fmt("#%llu", (unsigned long long)ent.ordinal) : ent.name;
        ordinal = ent.ordinal;
        forwarder = ent.forwarder;
        return true;
    }
    uint64_t disp = 0;
    if (ex.find_nearest(addr, ent, disp)) {
        function = fmt("%s+0x%llx", ent.name.empty() ? "?" : ent.name.c_str(),
                       (unsigned long long)disp);
        ordinal = ent.ordinal;
        return true;
    }
    function = fmt("+0x%llx", (unsigned long long)(addr - m->base));
    return true;
}

CmdResult cmd_exports(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    // exports [module] [mask] [max]
    const ModuleInfo* m = nullptr;
    size_t idx = 0;
    if (!a.empty()) {
        m = e.module_by_name(a[0]);
        if (!m) return fail("not_found", "no such module: " + a[0]);
        idx = 1;
    } else {
        if (e.modules().empty()) return fail("not_found", "no modules loaded");
        m = &e.modules().front();
    }
    std::string mask = (idx < a.size()) ? a[idx] : std::string("*");
    uint64_t max = 200;
    if (idx + 1 < a.size() && !parse_u64(a[idx + 1], max)) return fail("bad_args", "invalid max");
    if (max == 0 || max > 5000) max = 200;

    Exports ex;
    ex.init(e.process(), m->base, m->name);
    std::string err;
    if (!ex.load(err)) return fail("export_failed", err);

    auto list = ex.enumerate(mask, (size_t)max);
    Json arr = Json::arr();
    std::string t = fmt("%s  base=%s  %zu export(s)\n", m->name.c_str(), hex8(m->base).c_str(),
                        ex.count());
    t += fmt("%-10s %-8s %-18s %s\n", "ordinal", "rva", "address", "name");
    t += std::string(60, '-') + "\n";
    for (auto& en : list) {
        Json j = Json::obj();
        j.set_str("name", en.name);
        j.set_u("ordinal", en.ordinal);
        j.set_hex("rva", en.rva);
        j.set_hex("address", en.address);
        if (!en.forwarder.empty()) j.set_str("forwarder", en.forwarder);
        arr.push(std::move(j));
        t += fmt("%-10llu %-8s %-18s %s%s\n", (unsigned long long)en.ordinal,
                 hex8(en.rva).c_str(), hex8(en.address).c_str(), en.name.c_str(),
                 en.forwarder.empty() ? "" : (" -> " + en.forwarder).c_str());
    }
    Json d = Json::obj();
    d.set_str("module", m->name);
    d.set_hex("base", m->base);
    d.set_u("count", ex.count());
    d.set("exports", arr);
    return ok(d, t);
}

// Walks a pointer-sized slot region and resolves every entry to
// module!function. Shared by `imports` and `iat map`.
bool walk_import_region(Engine& e, uint64_t addr, uint64_t count, Json& entries,
                        Json& by_module, std::string& text, std::string& err) {
    size_t ps = e.pointer_size();
    ExportCache cache{e};
    entries = Json::arr();
    std::map<std::string, Json> groups;
    text = fmt("%-18s %-18s %s\n", "slot", "value", "module!function");
    text += std::string(78, '-') + "\n";

    for (uint64_t i = 0; i < count; ++i) {
        uint64_t slot = addr + i * ps;
        uint64_t value = 0;
        std::string e2;
        if (!read_memory(e.process(), slot, &value, ps, e2)) {
            if (i == 0) {
                err = e2.empty() ? "cannot read the region" : e2;
                return false;
            }
            break;
        }
        if (!value) continue;

        std::string mod, fn, fwd;
        uint64_t ord = 0;
        bool resolved = resolve_import_slot(e, cache, value, mod, fn, ord, fwd);

        Json j = Json::obj();
        j.set_hex("slot", slot);
        j.set_hex("value", value);
        j.set_bool("resolved", resolved);
        if (resolved) {
            j.set_str("module", mod);
            j.set_str("function", fn);
            if (ord) j.set_u("ordinal", ord);
            if (!fwd.empty()) j.set_str("forwarder", fwd);
            auto it = groups.find(mod);
            if (it == groups.end()) it = groups.emplace(mod, Json::arr()).first;
            it->second.push(Json::s(fn));
        }
        entries.push(std::move(j));
        text += fmt("%-18s %-18s %s\n", hex8(slot).c_str(), hex8(value).c_str(),
                    resolved ? (mod + "!" + fn).c_str() : "<unresolved>");
    }

    by_module = Json::obj();
    for (auto& kv : groups) by_module.set(kv.first, kv.second);
    return true;
}

CmdResult cmd_imports(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (!need_args(a, 1, "imports <addr> [count]"))
        return fail("bad_args", "imports <addr> [count]");
    if (!e.is_paused()) return fail("not_paused", "target is not paused");
    uint64_t addr = 0;
    CmdResult dummy;
    if (!resolve(e, a[0], addr, dummy)) return dummy;
    uint64_t count = 32;
    if (a.size() > 1 && !parse_u64(a[1], count)) return fail("bad_args", "invalid count");
    if (count == 0 || count > 4096) return fail("bad_args", "count must be 1..4096");

    Json entries, bymod;
    std::string text, err;
    if (!walk_import_region(e, addr, count, entries, bymod, text, err))
        return fail("import_failed", err);

    Json d = Json::obj();
    d.set_hex("address", addr);
    d.set_u("count", entries.size());
    d.set_u("pointer_size", e.pointer_size());
    d.set("entries", entries);
    d.set("by_module", bymod);
    return ok(d, text);
}

CmdResult cmd_iat(Engine& e, CliConfig& cfg, const std::vector<std::string>& a) {
    std::string sub = a.empty() ? "map" : to_lower(a[0]);
    if (!e.is_paused()) return fail("not_paused", "target is not paused");

    if (sub == "scan") {
        // find regions that look like an IAT: dense runs of pointers into modules
        uint64_t start = 0, end = 0;
        if (a.size() > 1) {
            CmdResult dummy;
            if (!resolve(e, a[1], start, dummy)) return dummy;
        }
        if (a.size() > 2) {
            CmdResult dummy;
            if (!resolve(e, a[2], end, dummy)) return dummy;
        }
        size_t ps = e.pointer_size();
        auto regions = query_regions(e.process(), start, end);
        ExportCache cache{e};
        Json arr = Json::arr();
        std::string t = fmt("%-18s %-10s %-8s %-10s %s\n", "start", "size", "slots", "exports",
                            "modules");
        t += std::string(88, '-') + "\n";

        // An IAT is a *run* of consecutive module pointers inside a larger data
        // region, so scan for runs rather than judging whole regions. Scylla
        // does the same thing when it auto-detects an import table.
        for (auto& r : regions) {
            if (r.state != MEM_COMMIT) continue;
            if (r.protect & (PAGE_NOACCESS | PAGE_GUARD)) continue;
            size_t n = r.size / ps;
            if (n < 4 || n > 262144) continue;
            std::vector<uint64_t> vals(n);
            std::string e2;
            size_t got = 0;
            if (!read_memory(e.process(), r.base, vals.data(), n * ps, e2, &got)) continue;
            size_t got_n = got / ps;
            if (got_n < 4) continue;

            size_t run_start = 0, run_len = 0, run_exports = 0;
            std::set<std::string> run_mods;
            size_t gap = 0;
            auto flush_run = [&]() {
                if (run_len >= 4 && run_exports * 2 >= run_len && run_mods.size() >= 2) {
                    uint64_t s = r.base + run_start * ps;
                    Json j = Json::obj();
                    j.set_hex("start", s);
                    j.set_u("size", run_len * ps);
                    j.set_u("slots", run_len);
                    j.set_u("resolved_exports", run_exports);
                    j.set_u("module_count", run_mods.size());
                    arr.push(std::move(j));
                    t += fmt("%-18s %-10s %-8zu %-10zu %zu\n", hex8(s).c_str(),
                             fmt("0x%zx", run_len * ps).c_str(), run_len, run_exports,
                             run_mods.size());
                }
                run_len = 0;
                run_exports = 0;
                run_mods.clear();
            };

            for (size_t i = 0; i < got_n; ++i) {
                uint64_t v = vals[i];
                std::string m, f, fw;
                uint64_t o = 0;
                bool is_ptr = v && e.module_at(v);
                bool is_exp = is_ptr && resolve_import_slot(e, cache, v, m, f, o, fw);
                if (is_ptr) {
                    if (run_len == 0) run_start = i;
                    ++run_len;
                    if (is_exp) {
                        ++run_exports;
                        run_mods.insert(m);
                    }
                    gap = 0;
                } else {
                    // tolerate a little padding between entries
                    if (++gap > 2) flush_run();
                }
            }
            flush_run();
        }
        Json d = Json::obj();
        d.set("regions", arr);
        d.set_u("count", arr.size());
        return ok(d, arr.size() ? t : "no IAT-like region found\n");
    }

    if (sub == "map" || sub == "imports") {
        if (a.size() < 2) return fail("bad_args", "iat map <addr> [count]");
        std::vector<std::string> rest(a.begin() + 1, a.end());
        return cmd_imports(e, cfg, rest);
    }

    // Build the callback bundle both `refs` and `fix` need.
    auto make_input = [&e](ExportCache& cache) {
        ImportFixInput in;
        in.is32 = e.is32();
        in.read = [&e](uint64_t ad, void* b, size_t n, std::string& er) {
            size_t got = 0;
            return read_memory(e.process(), ad, b, n, er, &got) && got == n;
        };
        in.write = [&e](uint64_t ad, const void* b, size_t n, std::string& er) {
            return write_memory(e.process(), ad, b, n, er);
        };
        in.resolve = [&e, &cache](uint64_t api, std::string& mod, std::string& fn,
                                  uint64_t& ord) {
            std::string fwd;
            return resolve_import_slot(e, cache, api, mod, fn, ord, fwd);
        };
        return in;
    };

    if (sub == "refs") {
        if (a.size() < 3) return fail("bad_args", "iat refs <start> <end>");
        uint64_t start = 0, end = 0;
        CmdResult dummy;
        if (!resolve(e, a[1], start, dummy)) return dummy;
        if (!resolve(e, a[2], end, dummy)) return dummy;

        ExportCache cache{e};
        ImportFixInput in = make_input(cache);
        std::vector<ImportRef> refs;
        std::string err;
        if (!scan_import_refs(in, start, end, refs, err)) return fail("scan_failed", err);

        Json d = Json::obj();
        d.set_hex("start", start);
        d.set_hex("end", end);
        d.set_u("count", refs.size());
        d.set("references", import_refs_to_json(refs));
        return ok(d, refs.empty() ? "no import references found\n" : import_refs_to_text(refs));
    }

    if (sub == "fix") {
        if (a.size() < 3) return fail("bad_args", "iat fix <start> <end> [newva]");
        uint64_t start = 0, end = 0, newva = 0;
        CmdResult dummy;
        if (!resolve(e, a[1], start, dummy)) return dummy;
        if (!resolve(e, a[2], end, dummy)) return dummy;
        if (a.size() > 3 && !resolve(e, a[3], newva, dummy)) return dummy;

        ExportCache cache{e};
        ImportFixInput in = make_input(cache);
        std::vector<ImportRef> refs;
        std::string err;
        if (!scan_import_refs(in, start, end, refs, err)) return fail("scan_failed", err);
        if (refs.empty()) return fail("no_imports", "no import references in that range");

        // count distinct APIs so the table can be sized before it is written
        std::set<std::string> uniq;
        for (auto& r : refs) uniq.insert(r.module + "!" + r.function);
        size_t ps = e.pointer_size();

        if (!newva) {
            // the table must be within +/-2GB of the code for the patched
            // RIP-relative displacements to fit
            if (!alloc_memory_near(e.process(), uniq.size() * ps + 16, start, newva, err))
                return fail("alloc_failed", err);
        }

        Json report;
        if (!fix_import_refs(in, refs, newva, ps, report, err))
            return fail("fix_failed", err);

        std::string t = fmt("import table written at %s\n", hex8(newva).c_str());
        t += fmt("  unique imports: %llu\n",
                 (unsigned long long)report.get("unique_imports").as_u());
        t += fmt("  patched instructions: %llu\n",
                 (unsigned long long)report.get("patched_instructions").as_u());
        return ok(report, t);
    }

    if (sub == "trace") {
        if (a.size() < 2) return fail("bad_args", "iat trace <addr> [max_steps]");
        uint64_t addr = 0;
        CmdResult dummy;
        if (!resolve(e, a[1], addr, dummy)) return dummy;
        uint64_t max = 2000;
        if (a.size() > 2 && !parse_u64(a[2], max)) return fail("bad_args", "invalid max");

        Json report;
        std::string err;
        bool good = e.trace_import(addr, (size_t)max, report, err);
        if (!good) return fail("trace_failed", err.empty() ? "no export reached" : err);

        std::string t = fmt("%s -> %s!%s   (%llu step(s))\n", hex8(addr).c_str(),
                            report.get("module").as_str().c_str(),
                            report.get("function").as_str().c_str(),
                            (unsigned long long)report.get("steps").as_u());
        return ok(report, t);
    }

    return fail("bad_args",
                "usage: iat [scan [start end] | map <addr> [count] | refs <start> <end> | "
                "fix <start> <end> <newva> | trace <addr> [max_steps]]");
}

// ---------------------------------------------------- breakpoint on-hit cmd

CmdResult cmd_bpcmd(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (a.empty()) {  // list breakpoints that carry a command
        Json arr = Json::arr();
        std::string t;
        for (const auto& bp : e.bps.all()) {
            if (bp.command.empty()) continue;
            Json j = Json::obj();
            j.set_u("id", (uint64_t)bp.id);
            j.set_hex("address", bp.address);
            j.set_str("command", bp.command);
            arr.push(std::move(j));
            t += fmt("%-4d %-18s %s\n", bp.id, hex8(bp.address).c_str(), bp.command.c_str());
        }
        if (t.empty()) t = "(no breakpoint commands)\n";
        return ok(arr, t);
    }
    uint64_t id = 0;
    if (!parse_u64(a[0], id)) return fail("bad_args", "invalid breakpoint id");
    Breakpoint* bp = e.bps.find((int)id);
    if (!bp) return fail("no_breakpoint", "no breakpoint with id " + a[0]);

    if (a.size() == 1) {
        Json d = Json::obj();
        d.set_u("id", (uint64_t)bp->id);
        d.set_str("command", bp->command);
        return ok(d, bp->command.empty() ? "no command set\n"
                                        : fmt("command: %s\n", bp->command.c_str()));
    }
    std::string cmd;
    for (size_t i = 1; i < a.size(); ++i) cmd += (i > 1 ? " " : "") + a[i];
    if (cmd == "-") {
        bp->command.clear();
        Json d = Json::obj();
        d.set_u("id", (uint64_t)bp->id);
        return ok(d, fmt("command removed from breakpoint %d\n", bp->id));
    }
    bp->command = cmd;
    Json d = Json::obj();
    d.set_u("id", (uint64_t)bp->id);
    d.set_str("command", cmd);
    return ok(d, fmt("breakpoint %d will run: %s\n", bp->id, cmd.c_str()));
}

// --------------------------------------------------- module-load breakpoints

CmdResult cmd_bpload(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (a.empty()) {  // list
        Json arr = Json::arr();
        std::string t;
        for (const auto& p : e.module_breaks()) {
            arr.push(Json::s(p));
            t += fmt("  %s\n", p.c_str());
        }
        if (t.empty()) t = "(no module-load breakpoints)\n";
        return ok(arr, t);
    }
    std::string sub = to_lower(a[0]);
    if (sub == "clear") {
        e.clear_module_breaks();
        Json d = Json::obj();
        return ok(d, "module-load breakpoints cleared\n");
    }
    if (sub == "del") {
        if (a.size() < 2) return fail("bad_args", "bpload del <pattern>");
        std::string err;
        if (!e.del_module_break(a[1], err)) return fail("no_pattern", err);
        Json d = Json::obj();
        return ok(d, fmt("removed module-load breakpoint %s\n", a[1].c_str()));
    }
    std::string pat = (sub == "add" && a.size() > 1) ? a[1] : a[0];
    std::string err;
    if (!e.add_module_break(pat, err)) return fail("bad_pattern", err);
    Json d = Json::obj();
    d.set_str("pattern", pat);
    return ok(d, fmt("will stop when a module matching '%s' loads\n", pat.c_str()));
}

// ------------------------------------------------------- user notes (labels)

// address -> (module, rva) anchor for the notes store
static bool note_anchor(Engine& e, const std::string& addr_text, std::string& module,
                        uint64_t& rva, std::string& err) {
    uint64_t addr = 0;
    if (!e.eval(addr_text, addr, err)) return false;
    const ModuleInfo* m = e.module_at(addr);
    if (!m) {
        err = "address is not inside a loaded module (notes are anchored to module+RVA)";
        return false;
    }
    module = m->name;
    rva = addr - m->base;
    return true;
}

CmdResult cmd_label(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (a.empty()) return fail("bad_args", "label <addr> [name|-]");
    std::string module;
    uint64_t rva = 0, addr = 0;
    std::string err;
    if (!note_anchor(e, a[0], module, rva, err)) return fail("bad_address", err);
    e.eval(a[0], addr, err);

    if (a.size() < 2) {  // show
        const Note* n = e.notes.find(module, rva);
        Json d = Json::obj();
        d.set_str("module", module);
        d.set_hex("rva", rva);
        d.set_hex("address", addr);
        if (n && !n->label.empty()) {
            d.set_str("label", n->label);
            return ok(d, fmt("%s = %s+%s\n", n->label.c_str(), module.c_str(),
                             hex8(rva).c_str()));
        }
        return ok(d, fmt("no label at %s (%s+%s)\n", hex8(addr).c_str(), module.c_str(),
                         hex8(rva).c_str()));
    }
    if (a[1] == "-") {
        e.notes.remove_label(module, rva);
        Json d = Json::obj();
        d.set_str("module", module);
        d.set_hex("rva", rva);
        return ok(d, fmt("label removed at %s\n", hex8(addr).c_str()));
    }
    if (!e.notes.set_label(module, rva, a[1], err)) return fail("bad_label", err);
    Json d = Json::obj();
    d.set_str("module", module);
    d.set_hex("rva", rva);
    d.set_hex("address", addr);
    d.set_str("label", a[1]);
    return ok(d, fmt("%s = %s+%s (address %s)\n", a[1].c_str(), module.c_str(),
                     hex8(rva).c_str(), hex8(addr).c_str()));
}

CmdResult cmd_comment(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    if (a.empty()) return fail("bad_args", "comment <addr> [text|-]");
    std::string module;
    uint64_t rva = 0, addr = 0;
    std::string err;
    if (!note_anchor(e, a[0], module, rva, err)) return fail("bad_address", err);
    e.eval(a[0], addr, err);

    if (a.size() < 2) {
        const Note* n = e.notes.find(module, rva);
        Json d = Json::obj();
        d.set_str("module", module);
        d.set_hex("rva", rva);
        d.set_hex("address", addr);
        if (n && !n->comment.empty()) {
            d.set_str("comment", n->comment);
            return ok(d, fmt("%s: %s\n", hex8(addr).c_str(), n->comment.c_str()));
        }
        return ok(d, fmt("no comment at %s\n", hex8(addr).c_str()));
    }
    std::string text;
    for (size_t i = 1; i < a.size(); ++i) text += (i > 1 ? " " : "") + a[i];
    if (text == "-") {
        e.notes.remove_comment(module, rva);
    } else {
        e.notes.set_comment(module, rva, text);
    }
    Json d = Json::obj();
    d.set_str("module", module);
    d.set_hex("rva", rva);
    d.set_hex("address", addr);
    if (text != "-") d.set_str("comment", text);
    return ok(d, fmt("%s %s at %s\n", text == "-" ? "comment removed:" : "comment set:",
                     text == "-" ? "" : ("\"" + text + "\"").c_str(), hex8(addr).c_str()));
}

CmdResult cmd_notes(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    std::string sub = a.empty() ? "list" : to_lower(a[0]);
    if (sub == "list" || sub == "ls") {
        Json d = e.notes.to_json();
        std::string t = fmt("%-24s %-10s %-20s %s\n", "module", "rva", "label", "comment");
        t += std::string(76, '-') + "\n";
        for (size_t i = 0; i < d.size(); ++i) {
            const Json& n = d.at(i);
            t += fmt("%-24s %-10s %-20s %s\n", n.get("module").as_str().c_str(),
                     n.get("rva").as_str().c_str(), n.get("label").as_str().c_str(),
                     n.get("comment").as_str().c_str());
        }
        t += fmt("%zu note(s)\n", d.size());
        return ok(d, t);
    }
    if (sub == "clear") {
        e.notes.clear();
        Json d = Json::obj();
        return ok(d, "notes cleared\n");
    }
    if (sub == "save" || sub == "load") {
        if (a.size() < 2) return fail("bad_args", "notes " + sub + " <file>");
        std::string err;
        if (sub == "save") {
            if (!e.notes.save(a[1], err)) return fail("save_failed", err);
            Json d = Json::obj();
            d.set_str("file", a[1]);
            d.set_u("count", e.notes.count());
            return ok(d, fmt("saved %zu note(s) to %s\n", e.notes.count(), a[1].c_str()));
        }
        if (!e.notes.load(a[1], err)) return fail("load_failed", err);
        Json d = Json::obj();
        d.set_str("file", a[1]);
        d.set_u("count", e.notes.count());
        return ok(d, fmt("loaded, %zu note(s) total\n", e.notes.count()));
    }
    return fail("bad_args", "usage: notes [list | save <file> | load <file> | clear]");
}

// ------------------------------------------------------------ anti-anti-debug

CmdResult cmd_detect(Engine& e, CliConfig&, const std::vector<std::string>&) {
    if (!e.active()) return fail("no_target", "no active target");
    std::string text;
    Json d = e.hide.detect_json(text);
    return ok(d, text);
}

CmdResult cmd_hide(Engine& e, CliConfig&, const std::vector<std::string>& a) {
    std::string sub = a.empty() ? "status" : to_lower(a[0]);

    auto report_ok = [&](const std::string& what) {
        Json d = e.hide.status_json();
        std::string t = fmt("hide: %s (profile: %s)\n",
                            e.hide.enabled() ? "enabled" : "disabled",
                            e.hide.profile().c_str());
        t += fmt("  %s\n", what.c_str());
        for (const auto& k : hide_keys())
            t += fmt("  %-34s %s\n", k.key, e.hide.config().*(k.field) ? "on" : "off");
        t += fmt("  hook sites planted: %llu\n",
                 (unsigned long long)d.get("hook_sites_planted").as_u());
        return ok(d, t);
    };

    if (sub == "status") return report_ok("configuration:");

    if (sub == "profiles") {
        Json d = hide_catalog_json();
        std::string t = "profiles:\n";
        for (const auto& name : hide_profile_names()) {
            HideConfig c;
            hide_profile_config(name, c);
            size_t on = 0;
            for (const auto& k : hide_keys())
                if (c.*(k.field)) on++;
            t += fmt("  %-12s %zu/%zu switches on\n", name.c_str(), on, hide_keys().size());
        }
        return ok(d, t);
    }

    if (sub == "on" || sub == "off") {
        if (sub == "on" && a.size() >= 2) {
            HideConfig c;
            if (!hide_profile_config(a[1], c))
                return fail("bad_profile",
                            "unknown profile (see 'hide profiles'): " + a[1]);
            e.hide.apply_config(c, to_lower(a[1]));
        }
        e.hide.set_enabled(sub == "on");
        return report_ok(sub == "on" ? "enabled" : "disabled");
    }

    if (sub == "profile") {
        if (a.size() < 2) return fail("bad_args", "hide profile <name>");
        HideConfig c;
        if (!hide_profile_config(a[1], c))
            return fail("bad_profile", "unknown profile (see 'hide profiles'): " + a[1]);
        e.hide.apply_config(c, to_lower(a[1]));
        return report_ok("profile applied: " + to_lower(a[1]));
    }

    if (sub == "set") {
        if (a.size() < 3) return fail("bad_args", "hide set <key> <0|1>");
        std::string v = to_lower(a[2]);
        bool on = v == "1" || v == "true" || v == "on";
        std::string err;
        if (!hide_set_key(e.hide.config(), a[1], on, err)) return fail("bad_key", err);
        e.hide.apply_config(e.hide.config(), e.hide.profile() + "+custom");
        return report_ok("switch set: " + a[1] + (on ? "=on" : "=off"));
    }

    if (sub == "apply") {
        e.hide.reapply();
        return report_ok("re-applied to every live process");
    }

    if (sub == "hooks") {
        Json d = e.hide.hooks_json();
        std::string t = fmt("%-8s %-28s %-18s %-8s %s\n", "pid", "api", "address", "planted",
                            "hits");
        t += std::string(76, '-') + "\n";
        for (size_t i = 0; i < d.size(); ++i) {
            const Json& h = d.at(i);
            t += fmt("%-8llu %-28s %-18s %-8s %llu\n", (unsigned long long)h.get("pid").as_u(),
                     h.get("api").as_str().c_str(), h.get("address").as_str().c_str(),
                     h.get("planted").as_bool() ? "yes" : "no",
                     (unsigned long long)h.get("hits").as_u());
        }
        return ok(d, t);
    }

    if (sub == "load" || sub == "save") {
        if (a.size() < 2) return fail("bad_args", "hide " + sub + " <file>");
        std::string err;
        if (sub == "save") {
            if (!hide_save_ini(e.hide.config(), a[1], err)) return fail("save_failed", err);
            return report_ok("saved to " + a[1]);
        }
        Json rep;
        HideConfig c = e.hide.config();
        if (!hide_load_ini(c, a[1], rep, err)) return fail("load_failed", err);
        e.hide.apply_config(c, e.hide.profile() + "+ini");
        Json d = e.hide.status_json();
        d.set("ini", rep);
        std::string t = fmt("hide: loaded '%s' (section [%s])\n", a[1].c_str(),
                            rep.get("section").as_str().c_str());
        t += fmt("  applied: %llu key(s), ignored: %llu key(s)\n",
                 (unsigned long long)rep.get("applied").size(),
                 (unsigned long long)rep.get("ignored").size());
        return ok(d, t);
    }

    return fail("bad_args",
                "usage: hide [status | on [profile] | off | profile <name> | "
                "set <key> <0|1> | apply | hooks | profiles | load <file> | save <file>]");
}

// ------------------------------------------------------------------ table

struct CmdSpec {
    const char* name;
    const char* aliases;
    const char* usage;
    const char* help;
    bool needs_target;
    bool needs_paused;
    CmdResult (*fn)(Engine&, CliConfig&, const std::vector<std::string>&);
};

const CmdSpec kCmds[] = {
    {"help", "", "help", "show this command list", false, false, cmd_help},
    {"file", "target", "file <path> [args...]", "set the executable to debug", false, false, cmd_file},
    {"run", "launch", "run [args...]", "launch the target and break at its entry point", false, false, cmd_run},
    {"attach", "", "attach <pid>", "attach to a running process", false, false, cmd_attach},
    {"detach", "", "detach", "detach from the target, leaving it running", true, false, cmd_detach},
    {"kill", "", "kill", "terminate the target", true, false, cmd_kill},
    {"restart", "", "restart", "kill and launch again", false, false, cmd_restart},
    {"aslr", "", "aslr [on|off]", "fix the load base to the PE ImageBase (default off = fixed)", false, false, cmd_aslr},
    {"info", "", "info", "show session state", false, false, cmd_info},
    {"version", "", "version", "show version", false, false, cmd_version},

    {"continue", "c,g", "continue [timeout_ms]", "resume execution", true, true, cmd_cont},
    {"step", "si,t", "step [count]", "single step, stepping into calls", true, true, cmd_step},
    {"next", "n,so,p", "next [count]", "single step, stepping over calls", true, true, cmd_next},
    {"finish", "gu", "finish", "run until the current function returns", true, true, cmd_finish},
    {"until", "u", "until <addr|expr>", "run to an address", true, true, cmd_until},
    {"stepuntil", "tu,traceuntil", "stepuntil <condition> [max_steps]", "single step until an expression is true", true, true, cmd_stepuntil},
    {"rununtil", "ru,pauseuntil", "rununtil <condition> [max_cycles]", "continue until an expression is true (checked at every stop)", true, true, cmd_rununtil},
    {"autostep", "astep", "autostep <count> [delay_ms]", "single step repeatedly and record the executed instruction trace", true, true, cmd_autostep},

    {"break", "b,bp", "break <addr|symbol> [condition]", "set a software breakpoint (works before the target starts)", false, false, cmd_break},
    {"hbreak", "hw,hr,he", "hbreak <addr|symbol> [r|w|x] [size]", "set a hardware breakpoint (max 4)", false, false, cmd_hbreak},
    {"mbreak", "mbp", "mbreak <addr> <size> [r|w|x]", "set a memory (guard page) breakpoint", false, false, cmd_mbreak},
    {"cond", "", "cond <id> <expression>", "set a breakpoint condition", false, false, cmd_cond},
    {"bpcmd", "", "bpcmd <id> [command|-]", "set/show/clear a command that runs at every hit of a breakpoint", false, false, cmd_bpcmd},
    {"bpload", "", "bpload [pattern|add <pattern>|del <pattern>|clear]", "stop when a module matching the pattern loads (e.g. 'bpload dbghelp.dll')", false, false, cmd_bpload},
    {"bl", "blist", "bl", "list breakpoints", false, false, cmd_bl},
    {"be", "", "be <id>", "enable a breakpoint", false, false, cmd_be},
    {"bd", "", "bd <id>", "disable a breakpoint", false, false, cmd_bd},
    {"bc", "", "bc <id|*>", "delete breakpoint(s)", false, false, cmd_bc},

    {"regs", "r", "regs [register...]", "show registers", true, true, cmd_regs},
    {"setreg", "", "setreg <register> <value>", "write a register", true, true, cmd_setreg},
    {"mem", "db", "mem <addr> [size]", "hex dump memory (default 64 bytes)", true, true, cmd_mem},
    {"read", "", "read <addr> <size>", "read bytes as hex", true, true, cmd_read},
    {"write", "", "write <addr> <hexbytes>", "write bytes", true, true, cmd_write},
    {"search", "find", "search <start> <end> <pattern> [max=N]", "byte pattern search (?? = wildcard)", true, true, cmd_search},
    {"regions", "maps", "regions [start] [end]", "list memory regions", true, true, cmd_regions},
    {"alloc", "", "alloc <size>", "allocate memory in the target", true, true, cmd_alloc},
    {"free", "", "free <addr>", "free allocated memory", true, true, cmd_free},
    {"protect", "", "protect <addr> <size> <r|w|x>", "change page protection", true, true, cmd_protect},

    {"disasm", "u,dis", "disasm [addr] [count]", "disassemble instructions", true, true, cmd_disasm},
    {"flow", "cfg,cfgv", "flow [addr] [max_blocks]", "control-flow graph of the containing function (basic blocks and edges)", true, true, cmd_flow},
    {"modules", "mods", "modules", "list loaded modules", true, false, cmd_modules},
    {"threads", "", "threads", "list threads", true, false, cmd_threads},
    {"thread", "", "thread <tid>", "switch the current thread", true, false, cmd_thread},
    {"processes", "ps", "processes", "list every debuggee process (including children)", true, false, cmd_processes},
    {"process", "proc", "process <pid>", "switch the current process", true, false, cmd_process},
    {"stack", "bt,k", "stack [max]", "show the call stack", true, true, cmd_stack},
    {"teb", "", "teb [tid]", "show the thread environment block of a thread", true, true, cmd_teb},
    {"peb", "", "peb", "show the process environment block (BeingDebugged, ImageBase, NtGlobalFlag...)", true, true, cmd_peb},
    {"heap", "", "heap [max_blocks]", "enumerate the target's heaps and their blocks", true, false, cmd_heap},
    {"handles", "", "handles [type] [max]", "enumerate the target's open handles", true, false, cmd_handles},
    {"symbols", "syms", "symbols [mask] [max]", "enumerate symbols", true, false, cmd_symbols},
    {"eval", "?", "eval <expression>", "evaluate an expression", true, false, cmd_eval},
    {"exports", "", "exports [module] [mask] [max]", "list a module's exports, parsed from the target's memory", true, true, cmd_exports},
    {"imports", "", "imports <addr> [count]", "resolve a run of pointers to module!function (IAT analysis)", true, true, cmd_imports},
    {"iat", "", "iat [scan [start end] | map <addr> [count] | refs <start> <end> | fix <start> <end> [newva]]", "find, analyse and rebuild import tables", true, true, cmd_iat},
    {"dump", "", "dump <file> [addr] [entry=<addr>] [compact] [keepbase]", "write the in-memory image out as a loadable PE file", true, true, cmd_dump},
    {"snapshot", "snap", "snapshot [save [name] | restore [name|index] | list | delete | clear | auto <on|off> | file [path] | history | load <id> | compact]",
     "save/restore process state; all snapshots live in one container file", false, false, cmd_snapshot},
    {"stepback", "sbk,reverse,dbk,debugback", "stepback [count]", "return to an earlier snapshot", true, true, cmd_stepback},
    {"ptype", "", "ptype <type>", "show the layout of a struct/union/enum (field offsets and types)", true, true, cmd_ptype},
    {"whatis", "", "whatis <symbol>", "show the declared type of a symbol", true, true, cmd_whatis},
    {"print", "p", "print <expression>", "type-aware evaluation with . / -> / [] member access", true, true, cmd_print},

    {"exlist", "ex", "exlist", "show the exception policy", true, false, cmd_exlist},
    {"exset", "", "exset <code> <break|ignore|pass>", "set exception handling policy", true, false, cmd_exset},
    {"exdel", "", "exdel <code>", "remove an exception rule", true, false, cmd_exdel},
    {"exall", "", "exall <on|off>", "ignore all first-chance exceptions", true, false, cmd_exall},

    {"label", "", "label <addr> [name|-]", "set/show/delete a user label at an address (usable in expressions, anchored to module+RVA)", true, false, cmd_label},
    {"comment", "", "comment <addr> [text|-]", "set/show/delete a user comment at an address", true, false, cmd_comment},
    {"notes", "", "notes [list | save <file> | load <file> | clear]", "manage user labels/comments and persist them to a JSON file", false, false, cmd_notes},

    {"detect", "", "detect", "check the target against the common debug-detection checks (al-khaser catalogue)", true, false, cmd_detect},
    {"hide", "", "hide [status | on [profile] | off | profile <name> | set <key> <0|1> | apply | hooks | profiles | load <file> | save <file>]",
     "anti-anti-debug: hide the debugger from the target (PEB patches + ntdll API virtualization)", false, false, cmd_hide},
};

const CmdSpec* find_spec(const std::string& name) {
    std::string n = to_lower(name);
    for (const auto& c : kCmds) {
        if (n == c.name) return &c;
        if (c.aliases && *c.aliases) {
            auto parts = split(c.aliases, ',');
            for (auto& p : parts)
                if (!p.empty() && n == p) return &c;
        }
    }
    return nullptr;
}

}  // namespace

Json command_catalog() {
    Json arr = Json::arr();
    for (const auto& c : kCmds) {
        Json j = Json::obj();
        j.set_str("name", c.name);
        if (c.aliases && *c.aliases) j.set_str("aliases", c.aliases);
        j.set_str("usage", c.usage);
        j.set_str("help", c.help);
        j.set_bool("needs_target", c.needs_target);
        j.set_bool("needs_paused", c.needs_paused);
        arr.push(std::move(j));
    }
    return arr;
}

CmdResult dispatch(Engine& eng, CliConfig& cfg, const std::string& line,
                   std::string& cmd_name) {
    std::string s = trim(line);
    if (s.empty() || s[0] == '#') {
        cmd_name = "";
        CmdResult r;
        r.data = Json::obj();
        return r;  // silently ignore blank lines and comments
    }
    auto parts = split_ws(s);
    if (parts.empty()) {
        cmd_name = "";
        CmdResult r;
        r.data = Json::obj();
        return r;
    }
    cmd_name = to_lower(parts[0]);
    std::vector<std::string> args(parts.begin() + 1, parts.end());

    // quit is handled by the caller but reported as a normal command
    if (cmd_name == "quit" || cmd_name == "exit" || cmd_name == "q") {
        CmdResult r;
        Json d = Json::obj();
        d.set_bool("quitting", true);
        r.data = d;
        r.text = "bye\n";
        return r;
    }

    const CmdSpec* spec = find_spec(cmd_name);
    if (!spec) {
        return CmdResult::fail("unknown_command",
                               "unknown command: " + cmd_name + " (try 'help')");
    }
    cmd_name = spec->name;
    if (spec->needs_target && !eng.active()) {
        return CmdResult::fail("no_target", "no active target - use 'run' or 'attach'");
    }
    return spec->fn(eng, cfg, args);
}

}  // namespace aj
