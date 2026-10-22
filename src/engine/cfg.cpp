#include "engine/cfg.h"

#include <algorithm>
#include <map>

#include "util/strutil.h"

namespace aj {

namespace {
constexpr size_t kMaxInsns = 2048;

bool is_block_end(const Insn& i) {
    return i.is_cond_jump || i.is_jump || i.is_ret || i.is_int || i.is_loop || i.is_syscall;
}
}  // namespace

bool build_cfg(const CfgInput& in, uint64_t addr, size_t max_blocks, Cfg& out,
               std::string& err) {
    out = Cfg();
    if (!disasm_init(in.is32)) {
        err = "disassembler is not available";
        return false;
    }

    // ---- function bounds ----------------------------------------------
    uint64_t start = 0, end = 0;
    std::string name;
    if (in.extent && in.extent(addr, start, end, name) && end > start) {
        out.func_start = start;
        out.func_end = end;
        out.func_name = name;
    } else {
        // no symbol: treat the current position as the start and stop at the
        // first ret that is not preceded by a jump target
        start = addr;
        out.func_start = addr;
        out.func_name = "<unknown>";
    }

    // ---- decode the whole range ---------------------------------------
    std::vector<Insn> insns;
    uint64_t p = start;
    uint64_t limit = (end > start) ? end : (start + 4096);
    while (p < limit && insns.size() < kMaxInsns) {
        uint8_t tmp[32] = {0};
        std::string e;
        if (!in.read(p, tmp, sizeof(tmp), e)) {
            out.truncated = true;
            break;
        }
        Insn insn;
        if (!decode_one(tmp, sizeof(tmp), p, insn, in.is32)) {
            out.truncated = true;
            break;
        }
        insns.push_back(insn);
        p += insn.length;
        // symbol-less fallback: stop after a ret with no pending branch target
        if (end <= start && insn.is_ret) break;
    }
    if (insns.empty()) {
        err = "no instructions decoded at " + hex8(addr);
        return false;
    }
    if (end <= start) out.func_end = insns.back().address + insns.back().length;
    out.instruction_count = insns.size();

    // ---- leaders (block starts) ----------------------------------------
    std::map<uint64_t, size_t> idx_of;
    for (size_t i = 0; i < insns.size(); ++i) idx_of[insns[i].address] = i;

    std::vector<uint64_t> leaders;
    leaders.push_back(insns.front().address);
    for (size_t i = 0; i < insns.size(); ++i) {
        const Insn& n = insns[i];
        if (n.has_target && n.target >= insns.front().address &&
            n.target <= insns.back().address && idx_of.count(n.target)) {
            leaders.push_back(n.target);
        }
        if (is_block_end(n) && i + 1 < insns.size()) leaders.push_back(insns[i + 1].address);
    }
    std::sort(leaders.begin(), leaders.end());
    leaders.erase(std::unique(leaders.begin(), leaders.end()), leaders.end());

    if (max_blocks > 0 && leaders.size() > max_blocks) {
        leaders.resize(max_blocks);
        out.truncated = true;
    }

    // ---- blocks ---------------------------------------------------------
    for (size_t li = 0; li < leaders.size(); ++li) {
        uint64_t bs = leaders[li];
        auto it = idx_of.find(bs);
        if (it == idx_of.end()) continue;
        size_t first = it->second;
        size_t last = first;
        uint64_t stop = (li + 1 < leaders.size()) ? leaders[li + 1]
                                                  : insns.back().address + insns.back().length;
        while (last + 1 < insns.size() && insns[last + 1].address < stop) ++last;

        CfgBlock b;
        b.start = bs;
        b.insns.assign(insns.begin() + (long)first, insns.begin() + (long)last + 1);
        b.end = b.insns.back().address + b.insns.back().length;
        b.terminator = b.insns.back().mnemonic;
        out.blocks.push_back(std::move(b));
    }

    // ---- edges ----------------------------------------------------------
    for (size_t bi = 0; bi < out.blocks.size(); ++bi) {
        CfgBlock& b = out.blocks[bi];
        const Insn& last = b.insns.back();
        bool has_next = (bi + 1 < out.blocks.size());

        if (last.is_ret || last.is_int) {
            b.is_exit = true;
            continue;
        }
        if (last.is_jump) {
            CfgEdge e;
            e.from = b.start;
            if (last.has_target) {
                e.to = last.target;
                e.kind = "branch";
                e.external = !idx_of.count(last.target);
            } else {
                e.kind = "indirect";  // jmp reg / jmp [mem]
            }
            b.edges.push_back(e);
            out.edges.push_back(e);
            continue;
        }
        if (last.is_cond_jump || last.is_loop) {
            CfgEdge e;
            e.from = b.start;
            if (last.has_target) {
                e.to = last.target;
                e.kind = "branch";
                e.external = !idx_of.count(last.target);
                b.edges.push_back(e);
                out.edges.push_back(e);
            } else {
                CfgEdge ind;
                ind.from = b.start;
                ind.kind = "indirect";
                b.edges.push_back(ind);
                out.edges.push_back(ind);
            }
            if (has_next) {
                CfgEdge f;
                f.from = b.start;
                f.to = out.blocks[bi + 1].start;
                f.kind = "fallthrough";
                b.edges.push_back(f);
                out.edges.push_back(f);
            }
            continue;
        }
        // ordinary instruction: fall through
        if (has_next) {
            CfgEdge f;
            f.from = b.start;
            f.to = out.blocks[bi + 1].start;
            f.kind = "fallthrough";
            b.edges.push_back(f);
            out.edges.push_back(f);
        } else {
            b.is_exit = true;
        }
    }
    return true;
}

Json cfg_to_json(const Cfg& c) {
    Json blocks = Json::arr();
    for (size_t i = 0; i < c.blocks.size(); ++i) {
        const CfgBlock& b = c.blocks[i];
        Json bj = Json::obj();
        bj.set_u("index", (uint64_t)i);
        bj.set_hex("start", b.start);
        bj.set_hex("end", b.end);
        bj.set_u("size", (uint64_t)b.insns.size());
        bj.set_str("terminator", b.terminator);
        bj.set_bool("exit", b.is_exit);

        Json edges = Json::arr();
        for (const auto& e : b.edges) {
            Json ej = Json::obj();
            if (e.to) ej.set_hex("to", e.to);
            ej.set_str("type", e.kind);
            if (e.external) ej.set_bool("external", true);
            edges.push(std::move(ej));
        }
        bj.set("edges", edges);

        Json ins = Json::arr();
        for (const auto& n : b.insns) {
            Json ij = Json::obj();
            ij.set_hex("address", n.address);
            ij.set_str("bytes", bytes_to_hex(n.bytes));
            ij.set_str("text", n.text);
            if (n.has_target) ij.set_hex("target", n.target);
            ins.push(std::move(ij));
        }
        bj.set("instructions", ins);
        blocks.push(std::move(bj));
    }

    Json fn = Json::obj();
    fn.set_str("name", c.func_name);
    fn.set_hex("start", c.func_start);
    fn.set_hex("end", c.func_end);

    Json d = Json::obj();
    d.set("function", fn);
    d.set("blocks", blocks);
    d.set_u("block_count", c.blocks.size());
    d.set_u("instruction_count", c.instruction_count);
    if (c.truncated) d.set_bool("truncated", true);
    return d;
}

std::string cfg_to_text(const Cfg& c, bool with_instructions) {
    std::string out = fmt("%s [%s - %s)  blocks=%zu instructions=%zu%s\n",
                          c.func_name.c_str(), hex8(c.func_start).c_str(),
                          hex8(c.func_end).c_str(), c.blocks.size(), c.instruction_count,
                          c.truncated ? "  (truncated)" : "");
    for (size_t i = 0; i < c.blocks.size(); ++i) {
        const CfgBlock& b = c.blocks[i];
        std::string ed;
        for (const auto& e : b.edges) {
            if (!ed.empty()) ed += ", ";
            if (e.kind == "indirect") {
                ed += "indirect";
            } else {
                ed += fmt("%s %s", e.to ? hex8(e.to).c_str() : "?", e.kind.c_str());
            }
        }
        out += fmt("block %zu  %s  [%zu insn]  -> %s%s\n", i, hex8(b.start).c_str(),
                   b.insns.size(), ed.empty() ? "(exit)" : ed.c_str(),
                   b.is_exit ? "  [exit]" : "");
        if (with_instructions) {
            for (const auto& n : b.insns) {
                out += fmt("    %s  %-24s %s\n", hex8(n.address).c_str(),
                           bytes_to_hex(n.bytes).c_str(), n.text.c_str());
            }
        }
    }
    return out;
}

}  // namespace aj
