#include "engine/breakpoints.h"

#include "engine/memory.h"
#include "util/strutil.h"

namespace aj {

std::string Breakpoint::access_text() const {
    if (kind == BpKind::Software) return "exec";
    std::string s;
    if (access & BP_ACC_READ) s += 'r';
    if (access & BP_ACC_WRITE) s += 'w';
    if (access & BP_ACC_EXEC) s += 'x';
    return s.empty() ? "-" : s;
}

int Breakpoints::add(Breakpoint bp) {
    bp.id = next_id_++;
    list_.push_back(std::move(bp));
    return list_.back().id;
}

bool Breakpoints::remove(int id) {
    for (size_t i = 0; i < list_.size(); ++i) {
        if (list_[i].id == id) {
            list_.erase(list_.begin() + (long)i);
            return true;
        }
    }
    return false;
}

bool Breakpoints::set_enabled(int id, bool enabled, std::string& err) {
    Breakpoint* bp = find(id);
    if (!bp) {
        err = fmt("no such breakpoint: %d", id);
        return false;
    }
    bp->enabled = enabled;
    return true;
}

Breakpoint* Breakpoints::find(int id) {
    for (auto& b : list_)
        if (b.id == id) return &b;
    return nullptr;
}

Breakpoint* Breakpoints::at_address(uint64_t addr) {
    for (auto& b : list_)
        if (b.address == addr && b.enabled && b.kind == BpKind::Software) return &b;
    return nullptr;
}

Breakpoint* Breakpoints::at_address_for_pid(uint64_t addr, uint32_t pid) {
    for (auto& b : list_) {
        if (!b.enabled || b.kind != BpKind::Software) continue;
        auto it = b.plants.find(pid);
        uint64_t a = (it != b.plants.end() && it->second.address) ? it->second.address : b.address;
        if (a == addr) return &b;
    }
    return nullptr;
}

bool Breakpoints::has_address(uint64_t addr) const {
    for (const auto& b : list_)
        if (b.enabled && b.kind == BpKind::Software && b.address == addr) return true;
    return false;
}

void Breakpoints::forget_plants() {
    for (auto& b : list_) {
        b.plants.clear();
        b.slot = -1;
    }
}

bool Breakpoints::plant_software(HANDLE proc, uint32_t pid, Breakpoint& bp, std::string& err,
                                 uint64_t addr) {
    BpPlant& pl = bp.plant_of(pid);
    if (!addr) addr = bp.address;
    pl.address = addr;
    if (pl.planted) return true;
    // Several breakpoints may occupy the same byte (a temporary step-over next
    // to a user breakpoint, or a duplicate). The first one owns the original
    // instruction byte; the others must not read the planted 0xCC as it.
    for (auto& other : list_) {
        if (&other == &bp || other.kind != BpKind::Software) continue;
        auto it = other.plants.find(pid);
        if (it == other.plants.end() || !it->second.planted) continue;
        uint64_t oa = it->second.address ? it->second.address : other.address;
        if (oa != addr) continue;
        pl.original_byte = it->second.original_byte;
        pl.planted = true;
        pl.present = true;
        return true;
    }
    uint8_t orig = 0;
    if (!read_memory(proc, addr, &orig, 1, err)) return false;
    uint8_t cc = 0xCC;
    if (!write_memory(proc, addr, &cc, 1, err)) return false;
    flush_icache(proc, addr, 1);
    pl.original_byte = orig;
    pl.planted = true;
    pl.present = true;
    return true;
}

bool Breakpoints::unplant_software(HANDLE proc, uint32_t pid, Breakpoint& bp, std::string& err) {
    BpPlant& pl = bp.plant_of(pid);
    if (!pl.planted) return true;
    uint64_t addr = pl.address ? pl.address : bp.address;
    // Keep the INT3 byte while another breakpoint still needs it.
    bool shared = false;
    for (auto& other : list_) {
        if (&other == &bp || other.kind != BpKind::Software) continue;
        auto it = other.plants.find(pid);
        if (it == other.plants.end() || !it->second.planted) continue;
        uint64_t oa = it->second.address ? it->second.address : other.address;
        if (oa == addr) {
            shared = true;
            break;
        }
    }
    if (!shared) {
        if (!write_memory(proc, addr, &pl.original_byte, 1, err)) return false;
        flush_icache(proc, addr, 1);
    }
    pl.planted = false;
    return true;
}

Json Breakpoints::to_json() const {
    Json arr = Json::arr();
    for (const auto& b : list_) {
        Json j = Json::obj();
        j.set_u("id", (uint64_t)b.id);
        j.set_str("kind", b.kind_text());
        j.set_hex("address", b.address);
        if (!b.symbol.empty()) j.set_str("symbol", b.symbol);
        j.set_u("size", (uint64_t)b.size);
        j.set_str("access", b.access_text());
        j.set_bool("enabled", b.enabled);
        if (b.temporary) j.set_bool("temporary", true);
        j.set_u("hit_count", b.hit_count);
        if (!b.condition.empty()) j.set_str("condition", b.condition);
        if (!b.command.empty()) j.set_str("command", b.command);
        if (b.kind == BpKind::Hardware) {
            j.set_i("slot", b.slot);
            if (b.thread_id) j.set_u("tid", b.thread_id);
        }
        if (b.kind == BpKind::Software || b.kind == BpKind::Memory) {
            Json ps = Json::arr();
            for (const auto& kv : b.plants) {
                if (!kv.second.present) continue;
                Json pj = Json::obj();
                pj.set_u("pid", kv.first);
                // "present" = the breakpoint applies to this process;
                // "armed"   = the INT3 / guard page is currently written, which is
                //             false while the session is parked on this breakpoint.
                pj.set_bool("present", true);
                pj.set_bool("armed", kv.second.planted);
                if (b.kind == BpKind::Memory) {
                    pj.set_hex("region_base", kv.second.region_base);
                    pj.set_u("region_size", (uint64_t)kv.second.region_size);
                }
                ps.push(std::move(pj));
            }
            if (ps.size()) j.set("processes", ps);
        }
        if (!b.resolved) j.set_bool("resolved", false);
        arr.push(std::move(j));
    }
    return arr;
}

std::string Breakpoints::to_text() const {
    if (list_.empty()) return "(no breakpoints)\n";
    std::string out = fmt("%-4s %-9s %-6s %-18s %-5s %-8s %s\n", "id", "kind", "access",
                          "address", "en", "hits", "symbol/condition");
    out += std::string(78, '-') + "\n";
    for (const auto& b : list_) {
        out += fmt("%-4d %-9s %-6s %-18s %-5s %-8llu %s%s%s%s%s\n", b.id, b.kind_text().c_str(),
                   b.access_text().c_str(), hex8(b.address).c_str(), b.enabled ? "yes" : "no",
                   (unsigned long long)b.hit_count,
                   b.symbol.empty() ? "" : b.symbol.c_str(),
                   b.condition.empty() ? "" : "  cond: ",
                   b.condition.c_str(),
                   b.command.empty() ? "" : "  cmd: ",
                   b.command.c_str());
    }
    return out;
}

}  // namespace aj
