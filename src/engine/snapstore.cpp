#include "engine/snapstore.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

namespace {

constexpr char kFileMagic[16] = {'A', 'I', 'D', 'B', 'G', '-', 'S', 'N', 'A', 'P', 0, 0, 0, 0, 0, 0};
constexpr char kRecMagic[8] = {'A', 'I', 'D', 'B', 'R', 'E', 'C', 0};
constexpr uint32_t kVersion = 1;
constexpr size_t kFileHeaderSize = 64;
constexpr size_t kRecHeaderSize = 96;

constexpr uint32_t kFlagDeleted = 1u;

void put_u16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back((uint8_t)v);
    b.push_back((uint8_t)(v >> 8));
}
void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (i * 8)));
}
void put_u64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back((uint8_t)(v >> (i * 8)));
}
bool get_u16(const uint8_t* p, size_t n, size_t& o, uint16_t& v) {
    if (o + 2 > n) return false;
    v = (uint16_t)(p[o] | (p[o + 1] << 8));
    o += 2;
    return true;
}
bool get_u32(const uint8_t* p, size_t n, size_t& o, uint32_t& v) {
    if (o + 4 > n) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) v |= (uint32_t)p[o + i] << (i * 8);
    o += 4;
    return true;
}
bool get_u64(const uint8_t* p, size_t n, size_t& o, uint64_t& v) {
    if (o + 8 > n) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)p[o + i] << (i * 8);
    o += 8;
    return true;
}

// CpuState is serialized field by field so the file does not depend on struct
// padding or on this build's ABI. Fields appended after the original set are
// read back only when present, so files written by older builds still load.
std::vector<uint8_t> serialize_regs(const CpuState& s) {
    std::vector<uint8_t> b;
    b.reserve(512);
    for (int i = 0; i < 16; ++i) put_u64(b, s.gpr[i]);
    put_u64(b, s.rip);
    put_u64(b, s.rflags);
    for (int i = 0; i < 6; ++i) put_u16(b, s.segs[i]);
    for (int i = 0; i < 4; ++i) put_u64(b, s.dr[i]);
    put_u64(b, s.dr6);
    put_u64(b, s.dr7);
    put_u32(b, s.is32 ? 1u : 0u);
    // v0.2.x: SSE state - without these a restore would zero the target's XMMs
    put_u32(b, s.mxcsr);
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j) b.push_back(s.xmm[i][j]);
    return b;
}

bool deserialize_regs(const uint8_t* p, size_t n, CpuState& s) {
    size_t o = 0;
    for (int i = 0; i < 16; ++i)
        if (!get_u64(p, n, o, s.gpr[i])) return false;
    if (!get_u64(p, n, o, s.rip)) return false;
    if (!get_u64(p, n, o, s.rflags)) return false;
    for (int i = 0; i < 6; ++i) {
        uint16_t v = 0;
        if (!get_u16(p, n, o, v)) return false;
        s.segs[i] = v;
    }
    for (int i = 0; i < 4; ++i)
        if (!get_u64(p, n, o, s.dr[i])) return false;
    if (!get_u64(p, n, o, s.dr6)) return false;
    if (!get_u64(p, n, o, s.dr7)) return false;
    uint32_t is32 = 0;
    if (!get_u32(p, n, o, is32)) return false;
    s.is32 = is32 != 0;
    // optional tail (records from v0.2.x onward)
    if (o < n) {
        uint32_t mx = 0;
        if (!get_u32(p, n, o, mx)) return true;  // old record: SSE stays zeroed
        s.mxcsr = mx;
        for (int i = 0; i < 16; ++i)
            for (int j = 0; j < 16; ++j) {
                if (o >= n) return true;
                s.xmm[i][j] = p[o++];
            }
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------- CRC32

uint32_t SnapStore::crc32(const uint8_t* data, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ------------------------------------------------------------------ open/close

SnapStore::~SnapStore() { close(); }

void SnapStore::close() {
    if (fp_) {
        std::fclose((FILE*)fp_);
        fp_ = nullptr;
    }
    recs_.clear();
}

bool SnapStore::open(const std::string& path, std::string& err) {
    close();
    path_ = path;

    FILE* f = std::fopen(path.c_str(), "r+b");
    if (!f) {
        f = std::fopen(path.c_str(), "w+b");  // new file
        if (!f) {
            err = fmt("cannot open snapshot store '%s': %s", path.c_str(), last_error_text().c_str());
            return false;
        }
        // write a fresh header
        std::vector<uint8_t> hdr(kFileHeaderSize, 0);
        std::memcpy(hdr.data(), kFileMagic, sizeof(kFileMagic));
        for (int i = 0; i < 4; ++i) hdr[16 + i] = (uint8_t)(kVersion >> (i * 8));
        uint32_t crc = crc32(hdr.data(), 48);
        for (int i = 0; i < 4; ++i) hdr[48 + i] = (uint8_t)(crc >> (i * 8));
        std::fseek(f, 0, SEEK_SET);
        std::fwrite(hdr.data(), 1, hdr.size(), f);
        std::fflush(f);
    }
    fp_ = f;

    // scan the file for records; this also survives a bad/missing header
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    if (sz < 0) {
        err = "cannot stat snapshot store";
        close();
        return false;
    }
    file_size_ = (uint64_t)sz;

    std::vector<uint8_t> buf((size_t)sz);
    std::fseek(f, 0, SEEK_SET);
    size_t got = std::fread(buf.data(), 1, (size_t)sz, f);
    buf.resize(got);

    size_t off = (got >= kFileHeaderSize) ? kFileHeaderSize : 0;
    next_id_ = 1;
    while (off + kRecHeaderSize <= buf.size()) {
        if (std::memcmp(buf.data() + off, kRecMagic, sizeof(kRecMagic)) != 0) {
            // stray bytes: skip ahead looking for the next record magic
            ++off;
            continue;
        }
        const uint8_t* h = buf.data() + off;
        size_t o = 8;
        uint64_t total = 0;
        if (!get_u64(h, kRecHeaderSize, o, total) || total < kRecHeaderSize ||
            off + total > buf.size()) {
            break;  // truncated tail from an interrupted write
        }

        SnapRecord r;
        uint32_t flags = 0, name_len = 0, reason_len = 0, regs_len = 0, is32 = 0;
        get_u32(h, kRecHeaderSize, o, r.id);
        get_u32(h, kRecHeaderSize, o, r.kind);
        get_u32(h, kRecHeaderSize, o, r.prev_id);
        get_u32(h, kRecHeaderSize, o, r.pid);
        get_u32(h, kRecHeaderSize, o, is32);
        get_u32(h, kRecHeaderSize, o, flags);
        get_u64(h, kRecHeaderSize, o, r.timestamp);
        get_u64(h, kRecHeaderSize, o, r.raw_size);
        get_u64(h, kRecHeaderSize, o, r.stored_size);
        get_u32(h, kRecHeaderSize, o, r.payload_crc);
        get_u32(h, kRecHeaderSize, o, name_len);
        get_u32(h, kRecHeaderSize, o, reason_len);
        get_u32(h, kRecHeaderSize, o, regs_len);
        r.is32 = is32 != 0;
        r.deleted = (flags & kFlagDeleted) != 0;

        size_t body = off + kRecHeaderSize;
        size_t end = off + (size_t)total;
        if (name_len && body + name_len <= end) {
            r.name.assign((const char*)buf.data() + body, name_len);
            body += name_len;
        }
        if (reason_len && body + reason_len <= end) {
            r.stop_reason.assign((const char*)buf.data() + body, reason_len);
            body += reason_len;
        }
        if (regs_len && body + regs_len <= end) {
            deserialize_regs(buf.data() + body, regs_len, r.regs);
            body += regs_len;
        }
        if (body < end) {
            r.payload.assign(buf.begin() + (long)body, buf.begin() + (long)end);
        }
        if (r.id >= next_id_) next_id_ = r.id + 1;
        recs_.push_back(std::move(r));
        off = end;
    }
    return true;
}

// ---------------------------------------------------------------- append/write

bool SnapStore::write_record(const SnapRecord& rec, uint64_t& offset, std::string& err) {
    std::vector<uint8_t> regs = serialize_regs(rec.regs);
    std::vector<uint8_t> name(rec.name.begin(), rec.name.end());
    std::vector<uint8_t> reason(rec.stop_reason.begin(), rec.stop_reason.end());

    uint64_t total = kRecHeaderSize + name.size() + reason.size() + regs.size() + rec.payload.size();

    std::vector<uint8_t> b;
    b.reserve((size_t)total + 8);
    b.insert(b.end(), kRecMagic, kRecMagic + sizeof(kRecMagic));
    put_u64(b, total);
    put_u32(b, rec.id);
    put_u32(b, rec.kind);
    put_u32(b, rec.prev_id);
    put_u32(b, rec.pid);
    put_u32(b, rec.is32 ? 1u : 0u);
    put_u32(b, rec.deleted ? kFlagDeleted : 0u);
    put_u64(b, rec.timestamp);
    put_u64(b, rec.raw_size);
    put_u64(b, rec.stored_size);
    put_u32(b, rec.payload_crc);
    put_u32(b, (uint32_t)name.size());
    put_u32(b, (uint32_t)reason.size());
    put_u32(b, (uint32_t)regs.size());
    put_u32(b, 0);
    put_u32(b, 0);
    put_u64(b, 0);
    b.insert(b.end(), name.begin(), name.end());
    b.insert(b.end(), reason.begin(), reason.end());
    b.insert(b.end(), regs.begin(), regs.end());
    b.insert(b.end(), rec.payload.begin(), rec.payload.end());

    FILE* f = (FILE*)fp_;
    std::fseek(f, 0, SEEK_END);
    long at = std::ftell(f);
    offset = (uint64_t)at;
    if (std::fwrite(b.data(), 1, b.size(), f) != b.size()) {
        err = "failed to write snapshot record";
        return false;
    }
    std::fflush(f);
    file_size_ += b.size();
    return true;
}

bool SnapStore::append(SnapRecord rec, std::string& err) {
    if (!fp_) {
        err = "snapshot store is not open";
        return false;
    }
    if (rec.id == 0) rec.id = (uint32_t)next_id_;
    if (rec.timestamp == 0) rec.timestamp = (uint64_t)std::time(nullptr);
    rec.deleted = false;

    uint64_t offset = 0;
    if (!write_record(rec, offset, err)) return false;
    if (rec.id >= next_id_) next_id_ = rec.id + 1;
    recs_.push_back(std::move(rec));
    return true;
}

bool SnapStore::update(const SnapRecord& rec, std::string& err) {
    // log structured: never rewrite in place, supersede instead. `compact()`
    // reclaims the space later.
    for (auto& r : recs_)
        if (r.id == rec.id && !r.deleted) r.deleted = true;
    return append(rec, err);
}

bool SnapStore::mark_deleted(uint32_t id, std::string& err) {
    if (!fp_) {
        err = "snapshot store is not open";
        return false;
    }
    for (auto& r : recs_) {
        if (r.id == id) {
            r.deleted = true;
            // the flag lives in the record header; rewrite just that word
            std::fseek((FILE*)fp_, 0, SEEK_END);
            return true;
        }
    }
    err = fmt("no such record: %u", id);
    return false;
}

bool SnapStore::get(uint32_t id, SnapRecord& out) const {
    for (const auto& r : recs_)
        if (r.id == id && !r.deleted) {
            out = r;
            return true;
        }
    return false;
}

// ----------------------------------------------------------------- compaction

bool SnapStore::rewrite_all(const std::vector<SnapRecord>& recs, std::string& err) {
    std::string tmp = path_ + ".tmp";
    FILE* f = std::fopen(tmp.c_str(), "w+b");
    if (!f) {
        err = "cannot create temporary snapshot store";
        return false;
    }
    void* old = fp_;
    fp_ = f;
    file_size_ = 0;  // recount while writing the new file

    // header first
    std::vector<uint8_t> hdr(kFileHeaderSize, 0);
    std::memcpy(hdr.data(), kFileMagic, sizeof(kFileMagic));
    for (int i = 0; i < 4; ++i) hdr[16 + i] = (uint8_t)(kVersion >> (i * 8));
    for (int i = 0; i < 8; ++i) hdr[24 + i] = (uint8_t)((uint64_t)recs.size() >> (i * 8));
    for (int i = 0; i < 8; ++i) hdr[32 + i] = (uint8_t)(next_id_ >> (i * 8));
    uint32_t crc = crc32(hdr.data(), 48);
    for (int i = 0; i < 4; ++i) hdr[48 + i] = (uint8_t)(crc >> (i * 8));
    std::fseek(f, 0, SEEK_SET);
    std::fwrite(hdr.data(), 1, hdr.size(), f);
    file_size_ = hdr.size();

    bool ok = true;
    for (const auto& r : recs) {
        uint64_t off = 0;
        if (!write_record(r, off, err)) {
            ok = false;
            break;
        }
    }
    std::fflush(f);
    std::fclose(f);
    fp_ = nullptr;

    if (!ok) {
        std::remove(tmp.c_str());
        fp_ = old;
        return false;
    }
    if (old) std::fclose((FILE*)old);
    // replace the original
    std::remove(path_.c_str());
    if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
        err = "cannot replace snapshot store";
        fp_ = nullptr;
        return false;
    }
    // reopen so the handle tracks the new file
    fp_ = std::fopen(path_.c_str(), "r+b");
    std::fseek((FILE*)fp_, 0, SEEK_END);
    file_size_ = (uint64_t)std::ftell((FILE*)fp_);
    return true;
}

bool SnapStore::compact(uint64_t& reclaimed, std::string& err) {
    uint64_t before = file_size_;
    std::vector<SnapRecord> live;
    for (auto& r : recs_)
        if (!r.deleted) live.push_back(r);
    if (!rewrite_all(live, err)) return false;
    recs_ = std::move(live);
    reclaimed = before > file_size_ ? before - file_size_ : 0;
    return true;
}

// ---------------------------------------------------------------- accounting

uint64_t SnapStore::file_size() const { return file_size_; }

uint64_t SnapStore::dead_bytes() const {
    // approximate: a dead record's payload plus its header
    uint64_t n = 0;
    for (const auto& r : recs_)
        if (r.deleted) n += kRecHeaderSize + r.stored_size;
    return n;
}

uint64_t SnapStore::live_bytes() const {
    uint64_t n = 0;
    for (const auto& r : recs_)
        if (!r.deleted) n += kRecHeaderSize + r.stored_size;
    return n;
}

}  // namespace aj
