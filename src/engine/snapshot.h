#pragma once
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "engine/registers.h"
#include "engine/snapstore.h"
#include "util/json.h"

namespace aj {

// One page of target memory. Empty `data` means the page was entirely zeros,
// which is the common case and costs nothing to store.
struct SnapPage {
    uint64_t addr = 0;      // page aligned
    uint32_t size = 0;
    DWORD protect = 0;
    std::vector<uint8_t> data;
};

// Snapshots are chained: the first is full, each later one records only the
// pages that differ from its predecessor. This mirrors how VM snapshots work
// and, unlike HDiffPatch's global matching, costs O(pages) to capture - which
// matters because the target is paused while we capture.
struct Snapshot {
    std::string name;
    uint64_t seq = 0;
    uint32_t pid = 0;
    bool is32 = false;
    CpuState regs;
    std::string stop_reason;

    bool is_base = true;             // true for a full snapshot
    std::vector<SnapPage> pages;     // base: every page; delta: only changed pages

    std::vector<uint8_t> blob;       // compressed form of `pages`
    bool has_blob = false;           // `pages` may then be empty to save RAM

    size_t stored_bytes = 0;         // bytes actually kept after compression
    size_t raw_bytes = 0;            // uncompressed payload size
    size_t stored_pages = 0;         // pages in this snapshot's own payload
    size_t region_bytes = 0;         // memory footprint covered (base only)
    size_t page_count = 0;           // pages in the effective (merged) map
};

class Snapshots {
public:
    void set_limits(size_t max_count, size_t max_bytes) {
        max_count_ = max_count;
        max_bytes_ = max_bytes;
    }
    void set_auto(bool on) { auto_ = on; }
    bool auto_enabled() const { return auto_; }
    size_t max_count() const { return max_count_; }
    size_t max_bytes() const { return max_bytes_; }

    // Reads the target and stores either a base snapshot or a delta of the
    // previously captured state.
    bool capture(HANDLE proc, bool is32, uint32_t pid, const CpuState& regs,
                 const std::string& stop_reason, const std::string& name, std::string& err);

    // Restores memory and registers, then discards anything captured later -
    // going back in time abandons the future.
    bool restore(HANDLE proc, HANDLE thread, size_t index, std::string& err);
    bool restore_by_name(HANDLE proc, HANDLE thread, const std::string& name, std::string& err);

    bool remove(size_t index);
    void clear();

    const std::vector<Snapshot>& list() const { return items_; }
    size_t count() const { return items_.size(); }
    size_t stored_bytes() const;
    size_t skipped_pages() const { return skipped_pages_; }

    bool find(const std::string& name, size_t& out) const;

    Json to_json() const;
    std::string to_text() const;

    // ---- single-file store --------------------------------------------
    // Every captured snapshot is appended to one container file, so a long
    // session never produces a pile of loose files. The in-memory ring stays
    // the fast path for stepback; the file is the durable history.
    bool open_store(const std::string& path, std::string& err);
    void close_store();
    bool store_open() const { return store_.is_open(); }
    const std::string& store_path() const { return store_.path(); }
    SnapStore& store() { return store_; }
    bool compact_store(uint64_t& reclaimed, std::string& err);
    // Restores a snapshot that is no longer cached in memory, replaying its
    // delta chain from the file.
    bool restore_from_store(uint32_t id, HANDLE proc, HANDLE thread, std::string& err);

private:
    bool store_pages(Snapshot& s, const std::vector<SnapPage>& pages, std::string& err);
    bool load_pages(const Snapshot& s, std::vector<SnapPage>& out, std::string& err) const;
    // payload <-> page list, independent of where the payload came from
    bool encode_pages(const std::vector<SnapPage>& pages, std::vector<uint8_t>& payload,
                      uint64_t& raw_size, std::string& err) const;
    bool decode_pages(const std::vector<uint8_t>& payload, uint64_t raw_size,
                      std::vector<SnapPage>& out, std::string& err) const;
    // merged page map of snapshots [0..index]
    bool effective_pages(size_t index, std::map<uint64_t, SnapPage>& out, std::string& err) const;
    bool reconstruct_from_store(uint32_t id, std::map<uint64_t, SnapPage>& out,
                                std::string& err) const;
    void enforce_limits();
    void drop_front();

    std::vector<Snapshot> items_;
    std::map<uint64_t, SnapPage> last_map_;  // effective map of the newest snapshot
    SnapStore store_;
    uint64_t last_seq_ = 0;   // seq of the most recent capture (chain link)
    bool auto_ = true;
    size_t max_count_ = 8;
    size_t max_bytes_ = 256 * 1024 * 1024;
    uint64_t seq_ = 0;
    size_t skipped_pages_ = 0;
};

}  // namespace aj
