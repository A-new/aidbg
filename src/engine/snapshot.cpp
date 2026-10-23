#include "engine/snapshot.h"

#include <compressapi.h>

#include <cstddef>
#include <cstring>
#include <ctime>

#include "engine/memory.h"
#include "engine/win_compat.h"
#include "util/strutil.h"

#pragma comment(lib, "cabinet.lib")

namespace aj {

namespace {

constexpr uint64_t kMaxAddress = 0x00007FFFFFFFFFFFULL;
constexpr uint32_t kPageSize = 4096;

bool is_all_zeros(const std::vector<uint8_t>& v) {
    for (uint8_t b : v)
        if (b) return false;
    return true;
}

// Only the documented page protection types are accepted from a snapshot
// file. Higher flag bits (e.g. PAGE_TARGETS_INVALID reported by
// VirtualQueryEx) are ignored rather than rejecting a legitimate snapshot.
bool valid_protection(uint32_t p) {
    switch (p & 0xFFu) {
        case PAGE_NOACCESS:
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

// Windows MS Compression (cabinet.dll): documented since Windows 8, no third
// party dependency, and XPRESS_HUFF compresses typical process memory well.
bool compress_blob(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    COMPRESSOR_HANDLE h = nullptr;
    if (!CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &h)) return false;
    SIZE_T need = 0;
    Compress(h, (PVOID)in.data(), in.size(), nullptr, 0, &need);
    if (need == 0) {
        CloseCompressor(h);
        return false;
    }
    out.resize(need);
    SIZE_T got = 0;
    BOOL ok = Compress(h, (PVOID)in.data(), in.size(), out.data(), out.size(), &got);
    CloseCompressor(h);
    if (!ok) return false;
    out.resize(got);
    return true;
}

bool decompress_blob(const std::vector<uint8_t>& in, size_t raw_size, std::vector<uint8_t>& out) {
    // raw_size comes from the (untrusted) record header. Refuse absurd sizes
    // instead of letting a crafted file drive a huge allocation.
    constexpr size_t kMaxRaw = 2ull * 1024 * 1024 * 1024;  // 2 GiB
    if (raw_size > kMaxRaw) return false;
    DECOMPRESSOR_HANDLE h = nullptr;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &h)) return false;
    out.resize(raw_size);
    SIZE_T got = 0;
    BOOL ok = Decompress(h, (PVOID)in.data(), in.size(), out.data(), out.size(), &got);
    CloseDecompressor(h);
    if (!ok) return false;
    out.resize(got);
    return true;
}

void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (i * 8)));
}
void put_u64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back((uint8_t)(v >> (i * 8)));
}
bool get_u32(const std::vector<uint8_t>& b, size_t& o, uint32_t& v) {
    if (o + 4 > b.size()) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) v |= (uint32_t)b[o + i] << (i * 8);
    o += 4;
    return true;
}
bool get_u64(const std::vector<uint8_t>& b, size_t& o, uint64_t& v) {
    if (o + 8 > b.size()) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)b[o + i] << (i * 8);
    o += 8;
    return true;
}

}  // namespace

// ------------------------------------------------------------- page payload

bool Snapshots::encode_pages(const std::vector<SnapPage>& pages, std::vector<uint8_t>& payload,
                             uint64_t& raw_size, std::string& err) const {
    std::vector<uint8_t> raw;
    raw.reserve(pages.size() * 24 + 64);
    put_u32(raw, (uint32_t)pages.size());
    for (const auto& p : pages) {
        put_u64(raw, p.addr);
        put_u32(raw, p.size);
        put_u32(raw, (uint32_t)p.protect);
        put_u32(raw, (uint32_t)p.data.size());
        raw.insert(raw.end(), p.data.begin(), p.data.end());
    }
    raw_size = raw.size();

    std::vector<uint8_t> packed;
    if (compress_blob(raw, packed) && packed.size() < raw.size()) {
        payload = std::move(packed);
    } else {
        payload = std::move(raw);
    }
    return true;
}

bool Snapshots::decode_pages(const std::vector<uint8_t>& payload, uint64_t raw_size,
                             std::vector<SnapPage>& out, std::string& err) const {
    out.clear();
    std::vector<uint8_t> raw;
    // a payload produced without a size win is stored uncompressed, so try the
    // decompressor first and fall back to the raw form
    if (!decompress_blob(payload, (size_t)raw_size, raw)) raw = payload;

    size_t o = 0;
    uint32_t n = 0;
    if (!get_u32(raw, o, n)) {
        err = "corrupt snapshot payload";
        return false;
    }
    // Each entry has a 20-byte header. A page count that cannot possibly fit
    // is a corrupt/hostile file, not something to reserve memory for.
    if (n > raw.size() / 20 || n > 4000000u) {
        err = "corrupt snapshot payload (page count)";
        return false;
    }
    out.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        SnapPage p;
        uint32_t size = 0, prot = 0, dlen = 0;
        if (!get_u64(raw, o, p.addr) || !get_u32(raw, o, size) || !get_u32(raw, o, prot) ||
            !get_u32(raw, o, dlen)) {
            err = "corrupt snapshot payload";
            return false;
        }
        // Validate before the data is ever handed to WriteProcessMemory or
        // VirtualProtectEx: a crafted .snap must not become an arbitrary
        // write / arbitrary protection primitive.
        if (p.addr == 0 || p.addr >= kMaxAddress || size == 0 || size > 0x10000 ||
            (dlen != 0 && dlen != size) || !valid_protection(prot)) {
            err = "corrupt snapshot payload (bad page)";
            return false;
        }
        p.size = size;
        p.protect = prot & 0x7FFu;  // keep only the documented protection bits
        if (dlen) {
            if (o + dlen > raw.size()) {
                err = "corrupt snapshot payload";
                return false;
            }
            p.data.assign(raw.begin() + (std::ptrdiff_t)o,
                          raw.begin() + (std::ptrdiff_t)(o + dlen));
            o += dlen;
        }
        out.push_back(std::move(p));
    }
    return true;
}

bool Snapshots::store_pages(Snapshot& s, const std::vector<SnapPage>& pages, std::string& err) {
    std::vector<uint8_t> payload;
    uint64_t raw = 0;
    if (!encode_pages(pages, payload, raw, err)) return false;
    s.raw_bytes = raw;
    s.stored_pages = pages.size();
    s.blob = std::move(payload);
    s.has_blob = true;
    s.stored_bytes = s.blob.size();
    s.pages.clear();  // the blob is authoritative from here on
    return true;
}

bool Snapshots::load_pages(const Snapshot& s, std::vector<SnapPage>& out, std::string& err) const {
    if (!s.has_blob) {
        out = s.pages;
        return true;
    }
    return decode_pages(s.blob, s.raw_bytes, out, err);
}

bool Snapshots::effective_pages(size_t index, std::map<uint64_t, SnapPage>& out,
                                std::string& err) const {
    out.clear();
    for (size_t i = 0; i <= index && i < items_.size(); ++i) {
        std::vector<SnapPage> pages;
        if (!load_pages(items_[i], pages, err)) return false;
        for (auto& p : pages) out[p.addr] = std::move(p);
    }
    return true;
}

// ------------------------------------------------------------------- capture

bool Snapshots::capture(HANDLE proc, bool is32, uint32_t pid, const CpuState& regs,
                        const std::string& stop_reason, const std::string& name,
                        std::string& err) {
    // read the target into a page-aligned map
    std::map<uint64_t, SnapPage> cur;
    size_t region_bytes = 0;

    uint64_t addr = 0;
    while (addr < kMaxAddress) {
        MemRegion reg;
        if (!region_at(proc, addr, reg) || reg.size == 0) break;
        bool readable = (reg.state == MEM_COMMIT) &&
                        !(reg.protect & (PAGE_NOACCESS | PAGE_GUARD));
        if (readable) {
            uint64_t p = reg.base;
            uint64_t end = reg.base + reg.size;
            while (p < end) {
                uint64_t chunk = kPageSize - (p & (kPageSize - 1));  // up to page boundary
                if (p + chunk > end) chunk = end - p;
                SnapPage pg;
                pg.addr = p;
                pg.size = (uint32_t)chunk;
                pg.protect = reg.protect;
                pg.data.resize((size_t)chunk);
                size_t got = 0;
                std::string e;
                if (!read_memory(proc, p, pg.data.data(), (size_t)chunk, e, &got) || got == 0)
                    break;
                pg.data.resize(got);
                pg.size = (uint32_t)got;
                region_bytes += got;
                if (is_all_zeros(pg.data)) pg.data.clear();
                cur[pg.addr] = std::move(pg);
                p += got;
            }
        }
        uint64_t next = reg.base + reg.size;
        if (next <= addr) break;
        addr = next;
    }
    if (cur.empty()) {
        err = "no readable memory captured";
        return false;
    }

    // the first snapshot is full; later ones record only what changed
    Snapshot s;
    s.name = name;
    s.seq = ++seq_;
    s.pid = pid;
    s.is32 = is32;
    s.regs = regs;
    s.stop_reason = stop_reason;
    s.region_bytes = region_bytes;
    s.page_count = cur.size();

    std::vector<SnapPage> payload;
    if (last_map_.empty()) {
        s.is_base = true;
        payload.reserve(cur.size());
        for (auto& kv : cur) payload.push_back(kv.second);
    } else {
        s.is_base = false;
        for (auto& kv : cur) {
            auto it = last_map_.find(kv.first);
            bool same = (it != last_map_.end()) && it->second.size == kv.second.size &&
                        it->second.protect == kv.second.protect && it->second.data == kv.second.data;
            if (!same) payload.push_back(kv.second);
        }
        // nothing changed at all is legal: store an empty delta
    }

    if (!store_pages(s, payload, err)) return false;

    // durably append to the single-file store when one is open
    const uint64_t prev_seq = last_seq_;
    if (store_.is_open()) {
        SnapRecord rec;
        rec.id = (uint32_t)s.seq;
        rec.kind = s.is_base ? 0u : 1u;
        rec.prev_id = prev_seq ? (uint32_t)prev_seq : 0xFFFFFFFFu;
        rec.pid = s.pid;
        rec.is32 = s.is32;
        rec.regs = s.regs;
        rec.name = s.name;
        rec.stop_reason = s.stop_reason;
        rec.timestamp = (uint64_t)std::time(nullptr);
        rec.raw_size = s.raw_bytes;
        rec.stored_size = s.stored_bytes;
        rec.payload = s.blob;
        rec.payload_crc = SnapStore::crc32(rec.payload.data(), rec.payload.size());
        std::string e2;
        store_.append(std::move(rec), e2);  // history is best effort
    }
    last_seq_ = s.seq;

    items_.push_back(std::move(s));
    last_map_ = std::move(cur);
    enforce_limits();
    return true;
}

// ------------------------------------------------------------------- restore

bool Snapshots::restore_by_name(HANDLE proc, HANDLE thread, const std::string& name,
                                std::string& err) {
    size_t idx = 0;
    if (!find(name, idx)) {
        err = name.empty() ? "no snapshot available" : ("no such snapshot: " + name);
        return false;
    }
    return restore(proc, thread, idx, err);
}

bool Snapshots::restore(HANDLE proc, HANDLE thread, size_t index, std::string& err) {
    if (index >= items_.size()) {
        err = fmt("snapshot index %zu out of range", index);
        return false;
    }

    // rebuild the merged map of snapshots [0..index]
    std::map<uint64_t, SnapPage> eff;
    if (!effective_pages(index, eff, err)) return false;

    // Write every page back. Empty `data` pages are all zeros. Some pages are
    // genuinely un-writable (shared data such as KUSER_SHARED_DATA), so a
    // failed page is skipped rather than aborting the restore.
    //
    // MEM_MAPPED pages are never written: they are views of section objects
    // shared with the system or other processes (feature/activation-context
    // state and friends), and a cross-process write permanently corrupts the
    // shared view - a target restored over its mapped pages died in
    // RtlFreeMemoryBlockLookaside during process teardown. MEM_IMAGE pages
    // stay eligible so self-modifying code (packers) still rolls back.
    std::vector<uint8_t> zeros;
    size_t written = 0, skipped = 0;
    for (auto& kv : eff) {
        const SnapPage& p = kv.second;
        std::string e;
        const uint8_t* src;
        size_t n;
        if (p.data.empty()) {
            if (zeros.size() < p.size) zeros.assign(p.size, 0);
            src = zeros.data();
            n = p.size;
        } else {
            src = p.data.data();
            n = p.data.size();
        }
        MemRegion preg;
        if (!region_at(proc, p.addr, preg) || preg.type == MEM_MAPPED) {
            ++skipped;
            continue;
        }
        if (!write_memory(proc, p.addr, src, n, e)) {
            ++skipped;
            continue;
        }
        flush_icache(proc, p.addr, n);
        ++written;
        // Page protections are deliberately NOT rewritten. write_memory
        // already puts each page back to the protection it found; forcing the
        // snapshotted value on top broke targets in other ways (a WRITECOPY
        // page privatizes to READWRITE for good, READONLY image pages degrade).
    }
    skipped_pages_ = skipped;
    if (written == 0) {
        err = "no pages could be restored";
        return false;
    }

    // registers last, so RIP lands where the snapshot was taken
    if (!aj::set_state(thread, items_[index].regs, err)) return false;

    // going back in time abandons everything captured after this point
    while (items_.size() > index + 1) items_.pop_back();
    last_map_ = std::move(eff);
    return true;
}

// ---------------------------------------------------------------- management

bool Snapshots::find(const std::string& name, size_t& out) const {
    if (name.empty()) {
        if (items_.empty()) return false;
        out = items_.size() - 1;
        return true;
    }
    uint64_t idx = 0;
    if (parse_u64(name, idx)) {
        if (idx < items_.size()) {
            out = (size_t)idx;
            return true;
        }
        return false;
    }
    for (size_t i = 0; i < items_.size(); ++i) {
        if (items_[i].name == name) {
            out = i;
            return true;
        }
    }
    return false;
}

void Snapshots::drop_front() {
    if (items_.size() < 2) {
        items_.clear();
        last_map_.clear();
        return;
    }
    // the new oldest must become self-contained: fold snapshot 0 into 1
    std::string err;
    std::map<uint64_t, SnapPage> merged;
    if (effective_pages(1, merged, err)) {
        std::vector<SnapPage> payload;
        payload.reserve(merged.size());
        for (auto& kv : merged) payload.push_back(kv.second);
        Snapshot& keep = items_[1];
        keep.is_base = true;
        store_pages(keep, payload, err);
    }
    items_.erase(items_.begin());
}

void Snapshots::enforce_limits() {
    auto over = [&]() {
        if (items_.size() > max_count_) return true;
        return stored_bytes() > max_bytes_;
    };
    while (items_.size() > 1 && over()) drop_front();
}

bool Snapshots::remove(size_t index) {
    if (index >= items_.size()) return false;
    // only the newest entry can be removed without breaking the delta chain
    if (index + 1 != items_.size()) return false;
    // the durable copy dies with it, or `snapshot history` keeps showing it
    // and `compact` can never reclaim its bytes
    if (store_.is_open()) {
        std::string serr;
        store_.mark_deleted((uint32_t)items_[index].seq, serr);  // history is best effort
    }
    items_.pop_back();
    // the new newest is now the delta reference
    std::string err;
    if (items_.empty()) {
        last_map_.clear();
    } else {
        effective_pages(items_.size() - 1, last_map_, err);
    }
    return true;
}

void Snapshots::clear() {
    items_.clear();
    last_map_.clear();
}

size_t Snapshots::stored_bytes() const {
    size_t n = 0;
    for (const auto& s : items_) n += s.stored_bytes;
    return n;
}

// ------------------------------------------------------------------ reporting

Json Snapshots::to_json() const {
    Json arr = Json::arr();
    for (size_t i = 0; i < items_.size(); ++i) {
        const Snapshot& s = items_[i];
        Json j = Json::obj();
        j.set_u("index", (uint64_t)i);
        j.set_str("name", s.name.empty() ? fmt("auto-%llu", (unsigned long long)s.seq) : s.name);
        j.set_u("seq", s.seq);
        j.set_u("pid", s.pid);
        j.set_str("arch", s.is32 ? "x86" : "x64");
        j.set_hex("rip", s.regs.rip);
        j.set_str("stop_reason", s.stop_reason);
        j.set_str("kind", s.is_base ? "full" : "delta");
        j.set_u("pages", s.stored_pages);
        j.set_u("total_pages", s.page_count);
        j.set_u("raw_bytes", s.raw_bytes);
        j.set_u("stored_bytes", s.stored_bytes);
        arr.push(std::move(j));
    }
    Json d = Json::obj();
    d.set("snapshots", arr);
    d.set_u("count", items_.size());
    d.set_u("stored_bytes", stored_bytes());
    d.set_bool("auto", auto_);
    d.set_u("max_count", max_count_);
    d.set_u("max_bytes", max_bytes_);
    return d;
}

std::string Snapshots::to_text() const {
    if (items_.empty()) return "(no snapshots)\n";
    std::string out = fmt("%-4s %-12s %-6s %-6s %-18s %-10s %-10s %s\n", "idx", "name", "kind",
                          "arch", "rip", "raw", "stored", "stop");
    out += std::string(88, '-') + "\n";
    for (size_t i = 0; i < items_.size(); ++i) {
        const Snapshot& s = items_[i];
        std::string name = s.name.empty() ? fmt("auto-%llu", (unsigned long long)s.seq) : s.name;
        out += fmt("%-4zu %-12s %-6s %-6s %-18s %-10s %-10s %s\n", i, name.c_str(),
                   s.is_base ? "full" : "delta", s.is32 ? "x86" : "x64",
                   hex8(s.regs.rip).c_str(), fmt("%zu KB", s.raw_bytes / 1024).c_str(),
                   fmt("%zu KB", s.stored_bytes / 1024).c_str(), s.stop_reason.c_str());
    }
    size_t raw_total = 0;
    for (const auto& s : items_) raw_total += s.raw_bytes;
    out += fmt("raw %zu KB -> stored %zu KB (%.1fx), auto capture: %s\n", raw_total / 1024,
               stored_bytes() / 1024, raw_total ? (double)raw_total / (double)stored_bytes() : 1.0,
               auto_ ? "on" : "off");
    return out;
}

// ------------------------------------------------------------------- store

bool Snapshots::open_store(const std::string& path, std::string& err) {
    if (!store_.open(path, err)) return false;
    // Record ids must keep increasing across sessions or they collide with
    // what the file already holds. The delta chain does NOT cross sessions:
    // a new target process has a different memory layout, so the first capture
    // of each session is a full snapshot (and reconstruct_from_store walks back
    // to exactly that boundary).
    if (store_.next_id() > 1) seq_ = store_.next_id() - 1;
    last_seq_ = 0;
    return true;
}

void Snapshots::close_store() { store_.close(); }

bool Snapshots::compact_store(uint64_t& reclaimed, std::string& err) {
    return store_.compact(reclaimed, err);
}

bool Snapshots::reconstruct_from_store(uint32_t id, std::map<uint64_t, SnapPage>& out,
                                       std::string& err) const {
    const std::vector<SnapRecord>& recs = store_.records();
    size_t target = recs.size();
    for (size_t i = 0; i < recs.size(); ++i) {
        if (recs[i].id == id && !recs[i].deleted) {
            target = i;
            break;
        }
    }
    if (target == recs.size()) {
        err = fmt("no snapshot with id %u in the store", id);
        return false;
    }

    // the delta chain starts at the nearest preceding full record
    size_t start = target;
    while (start > 0 && !recs[start].is_full()) --start;

    out.clear();
    for (size_t i = start; i <= target; ++i) {
        if (recs[i].deleted) continue;
        std::vector<SnapPage> pages;
        if (!decode_pages(recs[i].payload, recs[i].raw_size, pages, err)) return false;
        for (auto& p : pages) out[p.addr] = std::move(p);
    }
    return true;
}

bool Snapshots::restore_from_store(uint32_t id, HANDLE proc, HANDLE thread, std::string& err) {
    if (!store_.is_open()) {
        err = "no snapshot store is open";
        return false;
    }
    SnapRecord rec;
    if (!store_.get(id, rec)) {
        err = fmt("no snapshot with id %u in the store", id);
        return false;
    }

    std::map<uint64_t, SnapPage> eff;
    if (!reconstruct_from_store(id, eff, err)) return false;

    std::vector<uint8_t> zeros;
    size_t written = 0, skipped = 0;
    for (auto& kv : eff) {
        const SnapPage& p = kv.second;
        std::string e;
        const uint8_t* src;
        size_t n;
        if (p.data.empty()) {
            if (zeros.size() < p.size) zeros.assign(p.size, 0);
            src = zeros.data();
            n = p.size;
        } else {
            src = p.data.data();
            n = p.data.size();
        }
        // same rules as restore(): never write MEM_MAPPED views
        MemRegion preg;
        if (!region_at(proc, p.addr, preg) || preg.type == MEM_MAPPED) {
            ++skipped;
            continue;
        }
        if (!write_memory(proc, p.addr, src, n, e)) {
            ++skipped;
            continue;
        }
        flush_icache(proc, p.addr, n);
        ++written;
    }
    skipped_pages_ = skipped;
    if (written == 0) {
        err = "no pages could be restored";
        return false;
    }
    return aj::set_state(thread, rec.regs, err);
}

}  // namespace aj
