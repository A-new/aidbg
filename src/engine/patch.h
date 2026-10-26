#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "util/json.h"

namespace aj {

// One recorded byte edit inside a loaded module. Writes to module memory
// (write / patch commands) are tracked here, anchored to module+RVA like
// notes so they survive ASLR slides and restarts, and can be baked into a
// copy of the on-disk binary with `patch file`.
struct PatchRecord {
    int id = 0;
    std::string module;              // module file name, e.g. "target.exe"
    uint64_t rva = 0;
    std::vector<uint8_t> original;   // bytes before the first recorded edit
    std::vector<uint8_t> patched;    // bytes after the latest edit
};

class PatchMgr {
public:
    // Records an edit, merging it with an overlapping record of the same
    // module so `original` keeps the very first bytes ever seen. Returns the
    // record id (an existing one when the edit merged into it).
    int record(const std::string& module, uint64_t rva,
               const std::vector<uint8_t>& original,
               const std::vector<uint8_t>& patched);

    const PatchRecord* find(int id) const;
    bool remove(int id);
    void clear();

    std::vector<PatchRecord> all() const { return records_; }
    size_t count() const { return records_.size(); }

    // Records of one module, in id order; fails when the store spans several
    // modules and none was named.
    bool by_module(const std::string& module, std::vector<const PatchRecord*>& out,
                   std::string& err) const;

private:
    std::vector<PatchRecord> records_;  // in id order
    int next_id_ = 1;
};

// Writes `dst_path` as a copy of the PE file `src_path` with the given edits
// applied (each maps a module RVA to its patched bytes) and the PE checksum
// fixed. Fails without writing anything when an RVA has no raw file mapping
// (virtual-only data) or falls outside the file.
bool patch_file(const std::string& src_path, const std::string& dst_path,
                const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& edits,
                Json& report, std::string& err);

}  // namespace aj
