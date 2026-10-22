#pragma once
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

enum class BpKind { Software, Hardware, Memory };

// access bits for hardware / memory breakpoints
enum : uint8_t { BP_ACC_READ = 1, BP_ACC_WRITE = 2, BP_ACC_EXEC = 4 };

// Per-process planting state. A breakpoint can exist in several debuggee
// processes at once (child-process following), and each has its own original
// instruction byte and its own guard-page bookkeeping.
struct BpPlant {
    bool present = false;         // known to this process
    bool planted = false;         // software: INT3 written / memory: guard armed
    uint8_t original_byte = 0;
    uint64_t region_base = 0;     // memory breakpoint
    size_t region_size = 0;
    DWORD region_protect = 0;
};

struct Breakpoint {
    int id = 0;
    BpKind kind = BpKind::Software;
    uint64_t address = 0;
    size_t size = 1;
    uint8_t access = BP_ACC_EXEC;

    std::string condition;    // evaluated on hit, empty = always stop
    std::string symbol;       // original text ("kernel32!CreateFileW")
    std::string command;      // run on every hit (log-and-continue style)
    std::string temp_purpose; // step_over | step_out | run_until | entry
    bool enabled = true;
    bool temporary = false;
    uint64_t hit_count = 0;

    // hardware (DR0..DR3), shared across processes
    int slot = -1;
    DWORD thread_id = 0;      // 0 = apply to every thread

    // deferred until its module/symbol shows up
    bool resolved = true;

    // one entry per process this breakpoint lives in
    std::map<uint32_t, BpPlant> plants;

    BpPlant& plant_of(uint32_t pid) { return plants[pid]; }
    bool planted_anywhere() const {
        for (const auto& kv : plants)
            if (kv.second.planted) return true;
        return false;
    }

    std::string kind_text() const {
        switch (kind) {
            case BpKind::Software: return "software";
            case BpKind::Hardware: return "hardware";
            case BpKind::Memory: return "memory";
        }
        return "?";
    }
    std::string access_text() const;
};

class Breakpoints {
public:
    int add(Breakpoint bp);
    bool remove(int id);
    bool set_enabled(int id, bool enabled, std::string& err);
    Breakpoint* find(int id);
    Breakpoint* at_address(uint64_t addr);
    void clear() { list_.clear(); }

    std::vector<Breakpoint>& all() { return list_; }
    const std::vector<Breakpoint>& all() const { return list_; }

    // Software breakpoint planting, scoped to one process.
    bool plant_software(HANDLE proc, uint32_t pid, Breakpoint& bp, std::string& err);
    bool unplant_software(HANDLE proc, uint32_t pid, Breakpoint& bp, std::string& err);

    Json to_json() const;
    std::string to_text() const;

private:
    std::vector<Breakpoint> list_;
    int next_id_ = 1;
};

}  // namespace aj
