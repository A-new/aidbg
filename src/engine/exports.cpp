#include "engine/exports.h"

#include <cstring>

#include "engine/memory.h"
#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

namespace {
constexpr uint32_t kExportDirIndex = 0;
constexpr size_t kMaxExports = 65536;

// byte position of DataDirectory[0] inside the optional header
constexpr size_t kDataDirPE32 = 0x60;
constexpr size_t kDataDirPE32Plus = 0x70;
}  // namespace

bool Exports::read_at(uint64_t rva, void* buf, size_t n) const {
    std::string e;
    size_t got = 0;
    return read_memory(proc_, base_ + rva, buf, n, e, &got) && got == n;
}

bool Exports::read_str(uint64_t rva, std::string& out) const {
    out.clear();
    char buf[512];
    if (!read_at(rva, buf, sizeof(buf) - 1)) return false;
    buf[sizeof(buf) - 1] = 0;
    out.assign(buf, strnlen(buf, sizeof(buf) - 1));
    return true;
}

void Exports::init(HANDLE proc, uint64_t base, const std::string& module_name) {
    proc_ = proc;
    base_ = base;
    module_name_ = module_name;
    entries_.clear();
    by_addr_.clear();
    export_dir_rva_ = export_dir_size_ = 0;
}

bool Exports::load(std::string& err) {
    entries_.clear();
    by_addr_.clear();

    // ---- locate the export data directory --------------------------------
    uint8_t dos[0x40];
    if (!read_at(0, dos, sizeof(dos))) {
        err = "cannot read DOS header";
        return false;
    }
    uint32_t lfanew = *(uint32_t*)(dos + 0x3C);
    uint8_t nth[4 + 20 + 0x80];
    if (!read_at(lfanew, nth, sizeof(nth))) {
        err = "cannot read NT headers";
        return false;
    }
    const uint8_t* opt = nth + 4 + 20;
    uint16_t magic = *(uint16_t*)opt;
    size_t dir_off = 0;
    if (magic == 0x20B)
        dir_off = kDataDirPE32Plus;
    else if (magic == 0x10B)
        dir_off = kDataDirPE32;
    else {
        err = "not a PE image";
        return false;
    }

    export_dir_rva_ = *(uint32_t*)(opt + dir_off);
    export_dir_size_ = *(uint32_t*)(opt + dir_off + 4);
    if (!export_dir_rva_) return true;  // no exports at all

    // ---- IMAGE_EXPORT_DIRECTORY -----------------------------------------
    uint8_t ed[40];
    if (!read_at(export_dir_rva_, ed, sizeof(ed))) {
        err = "cannot read export directory";
        return false;
    }
    uint32_t base_ord = *(uint32_t*)(ed + 0x10);
    uint32_t nfuncs = *(uint32_t*)(ed + 0x14);
    uint32_t nnames = *(uint32_t*)(ed + 0x18);
    uint32_t addr_funcs = *(uint32_t*)(ed + 0x1C);
    uint32_t addr_names = *(uint32_t*)(ed + 0x20);
    uint32_t addr_ords = *(uint32_t*)(ed + 0x24);
    if (nfuncs == 0 || nfuncs > kMaxExports) return true;

    std::vector<uint32_t> funcs(nfuncs);
    if (!read_at(addr_funcs, funcs.data(), nfuncs * 4)) {
        err = "cannot read export address table";
        return false;
    }

    // name -> ordinal index
    std::map<uint32_t, std::string> name_of_index;
    uint32_t nnames_clamped = nnames > kMaxExports ? (uint32_t)kMaxExports : nnames;
    for (uint32_t i = 0; i < nnames_clamped; ++i) {
        uint32_t name_rva = 0, ord = 0;
        if (!read_at(addr_names + i * 4, &name_rva, 4)) break;
        if (!read_at(addr_ords + i * 2, &ord, 2)) break;
        std::string n;
        if (read_str(name_rva, n)) name_of_index[ord] = n;
    }

    entries_.reserve(nfuncs);
    for (uint32_t i = 0; i < nfuncs; ++i) {
        if (!funcs[i]) continue;
        ExportEntry e;
        e.ordinal = base_ord + i;
        e.rva = funcs[i];
        e.address = base_ + funcs[i];

        // an export RVA that lands inside the export directory is a forwarder
        if (funcs[i] >= export_dir_rva_ && funcs[i] < export_dir_rva_ + export_dir_size_) {
            read_str(funcs[i], e.forwarder);
        }
        auto it = name_of_index.find(i);
        if (it != name_of_index.end()) e.name = it->second;

        by_addr_[e.rva] = entries_.size();
        entries_.push_back(std::move(e));
    }
    return true;
}

bool Exports::find_by_address(uint64_t addr, ExportEntry& out) const {
    if (addr < base_) return false;
    auto it = by_addr_.find(addr - base_);
    if (it == by_addr_.end()) return false;
    out = entries_[it->second];
    return true;
}

bool Exports::find_nearest(uint64_t addr, ExportEntry& out, uint64_t& disp) const {
    if (addr < base_ || by_addr_.empty()) return false;
    uint64_t rva = addr - base_;
    auto it = by_addr_.upper_bound(rva);
    if (it == by_addr_.begin()) return false;
    --it;
    out = entries_[it->second];
    disp = rva - it->first;
    return true;
}

std::vector<ExportEntry> Exports::enumerate(const std::string& mask, size_t max) const {
    std::vector<ExportEntry> out;
    std::string want = to_lower(mask);
    for (const auto& e : entries_) {
        if (!want.empty() && want != "*") {
            // simple prefix match: "CreateFile*"
            std::string n = to_lower(e.name);
            bool match = false;
            if (!n.empty()) {
                if (want.size() > 1 && want.back() == '*')
                    match = n.compare(0, want.size() - 1, want, 0, want.size() - 1) == 0;
                else
                    match = (n == want);
            }
            if (!match) continue;
        }
        out.push_back(e);
        if (out.size() >= max) break;
    }
    return out;
}

Json Exports::to_json() const {
    Json arr = Json::arr();
    for (const auto& e : entries_) {
        Json j = Json::obj();
        j.set_str("name", e.name);
        j.set_u("ordinal", e.ordinal);
        j.set_hex("rva", e.rva);
        j.set_hex("address", e.address);
        if (!e.forwarder.empty()) j.set_str("forwarder", e.forwarder);
        arr.push(std::move(j));
    }
    Json d = Json::obj();
    d.set_str("module", module_name_);
    d.set_hex("base", base_);
    d.set("exports", arr);
    d.set_u("count", entries_.size());
    return d;
}

// ------------------------------------------------------------------- thunks

bool follow_thunk(HANDLE proc, uint64_t addr, uint64_t& out, int depth) {
    out = addr;
    for (int i = 0; i < depth; ++i) {
        uint8_t b[16] = {0};
        std::string e;
        size_t got = 0;
        if (!read_memory(proc, out, b, sizeof(b), e, &got) || got < 6) return true;

        // jmp qword ptr [rip+disp32]  (FF 25 xx xx xx xx)   x64
        if (b[0] == 0xFF && b[1] == 0x25) {
            int32_t rel = *(int32_t*)(b + 2);
            uint64_t slot = out + 6 + rel;
            uint64_t target = 0;
            if (!read_memory(proc, slot, &target, sizeof(target), e, &got)) return true;
            if (!target) return true;
            out = target;
            continue;
        }
        // jmp dword ptr [disp32]  (FF 24 25 xx xx xx xx)   x86 absolute
        if (b[0] == 0xFF && b[1] == 0x24 && b[2] == 0x25) {
            uint32_t slot = *(uint32_t*)(b + 3);
            uint32_t target = 0;
            if (!read_memory(proc, slot, &target, sizeof(target), e, &got)) return true;
            if (!target) return true;
            out = target;
            continue;
        }
        // jmp rel32  (E9 xx xx xx xx)
        if (b[0] == 0xE9) {
            int32_t rel = *(int32_t*)(b + 1);
            out = out + 5 + rel;
            continue;
        }
        // jmp [eax]/[rax] etc. cannot be followed statically
        return true;
    }
    return true;
}

}  // namespace aj
