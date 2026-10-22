#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "engine/registers.h"

namespace aj {

// One stored snapshot record. The payload is the serialized, compressed page
// list (see Snapshots::store_pages); everything else is metadata needed to
// rebuild the delta chain and the CPU state.
struct SnapRecord {
    uint32_t id = 0;
    uint32_t kind = 0;          // 0 = full (base), 1 = delta
    uint32_t prev_id = 0xFFFFFFFFu;  // id of the record this is a delta of
    uint32_t pid = 0;
    bool is32 = false;
    CpuState regs;
    std::string name;
    std::string stop_reason;
    uint64_t timestamp = 0;
    uint64_t raw_size = 0;
    uint64_t stored_size = 0;
    uint32_t payload_crc = 0;
    std::vector<uint8_t> payload;
    bool deleted = false;       // only meaningful after loading

    bool is_full() const { return kind == 0; }
};

// A single-file container for every snapshot of a debug session - think of it
// as a tiny append-only log rather than one file per snapshot.
//
// Why one file: a long session can accumulate hundreds of snapshots (deltas are
// ~1KB each), and scattering those into individual files makes them impossible
// to manage, back up or move around. One file is also the only sane way to keep
// the delta chain intact.
//
// Layout:
//   [FileHeader]                       fixed, at offset 0
//   [Record][Record]...                appended sequentially
//
// Records are self-describing (each carries its own total size), so the loader
// can rebuild the table by scanning. That means an interrupted write or a
// missing header never loses the snapshots that were already committed.
class SnapStore {
public:
    SnapStore() = default;
    ~SnapStore();

    SnapStore(const SnapStore&) = delete;
    SnapStore& operator=(const SnapStore&) = delete;

    // Opens (creating if needed) the container. Existing records are loaded.
    bool open(const std::string& path, std::string& err);
    void close();
    bool is_open() const { return fp_ != nullptr; }
    const std::string& path() const { return path_; }

    // Appends one record and returns its id.
    bool append(SnapRecord rec, std::string& err);
    // Replaces the record with the same id (used when re-basing a delta chain).
    bool update(const SnapRecord& rec, std::string& err);

    const std::vector<SnapRecord>& records() const { return recs_; }
    std::vector<SnapRecord>& records() { return recs_; }
    bool get(uint32_t id, SnapRecord& out) const;
    size_t count() const { return recs_.size(); }
    uint64_t next_id() const { return next_id_; }

    // Marks a record dead; space is reclaimed by compact().
    bool mark_deleted(uint32_t id, std::string& err);

    // Rewrites the file without dead records. Returns bytes reclaimed.
    bool compact(uint64_t& reclaimed, std::string& err);

    // Bytes currently occupied on disk and how much of that is dead.
    uint64_t file_size() const;
    uint64_t dead_bytes() const;
    uint64_t live_bytes() const;

    static uint32_t crc32(const uint8_t* data, size_t n);

private:
    bool write_record(const SnapRecord& rec, uint64_t& offset, std::string& err);
    bool rewrite_all(const std::vector<SnapRecord>& recs, std::string& err);

    std::string path_;
    void* fp_ = nullptr;              // FILE*
    std::vector<SnapRecord> recs_;    // live + deleted, in file order
    uint64_t next_id_ = 1;
    uint64_t file_size_ = 0;
};

}  // namespace aj
