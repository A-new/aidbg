#pragma once
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

struct ExportEntry {
    std::string name;
    uint32_t ordinal = 0;
    uint64_t rva = 0;
    uint64_t address = 0;
    std::string forwarder;   // "OTHERDLL.Func" when the export is forwarded
};

// Reads a module's export directory out of the debuggee's memory. This is the
// reverse half of import reconstruction: given an address, say which
// module!function it belongs to - exactly what Scylla does when it rebuilds an
// IAT after dumping a packed binary.
class Exports {
public:
    void init(HANDLE proc, uint64_t base, const std::string& module_name);

    // parses IMAGE_EXPORT_DIRECTORY; no exports is not an error
    bool load(std::string& err);

    bool empty() const { return by_addr_.empty() && entries_.empty(); }
    size_t count() const { return entries_.size(); }
    uint64_t base() const { return base_; }
    const std::string& module_name() const { return module_name_; }

    // exact address -> export
    bool find_by_address(uint64_t addr, ExportEntry& out) const;
    // nearest export at or below `addr`
    bool find_nearest(uint64_t addr, ExportEntry& out, uint64_t& disp) const;

    std::vector<ExportEntry> enumerate(const std::string& mask, size_t max) const;

    Json to_json() const;

private:
    bool read_at(uint64_t rva, void* buf, size_t n) const;
    bool read_str(uint64_t rva, std::string& out) const;

    HANDLE proc_ = nullptr;
    uint64_t base_ = 0;
    std::string module_name_;
    std::vector<ExportEntry> entries_;
    std::map<uint64_t, size_t> by_addr_;   // rva -> index into entries_
    uint64_t export_dir_rva_ = 0;
    uint64_t export_dir_size_ = 0;
};

// Follows a `jmp [rip+X]` / `jmp qword ptr [addr]` thunk to its target, which
// is where many IAT slots land instead of at the real function.
bool follow_thunk(HANDLE proc, uint64_t addr, uint64_t& out, int depth = 3);

}  // namespace aj
