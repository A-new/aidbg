#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// Reads the target's TEB / PEB and enumerates its heaps and handles.
//
// The structures live in the target's address space and their field offsets are
// stable across Windows versions for the handful of fields we report. Every
// reader returns what it found so the caller can sanity check (e.g. the PEB's
// ImageBaseAddress must equal the main module base).
struct TebInfo {
    uint64_t address = 0;
    uint64_t pid = 0;
    uint64_t tid = 0;
    uint64_t peb = 0;
    uint64_t stack_base = 0;
    uint64_t stack_limit = 0;
    uint64_t last_error = 0;
    uint64_t deallocation_stack = 0;
    bool is32 = false;
};

struct PebInfo {
    uint64_t address = 0;
    uint64_t image_base = 0;
    uint64_t ldr = 0;
    uint64_t process_parameters = 0;
    uint64_t process_heap = 0;
    uint64_t nt_global_flag = 0;
    uint32_t being_debugged = 0;
    uint32_t number_of_processors = 0;
    uint32_t session_id = 0;
    bool is32 = false;
};

struct HeapBlock {
    uint64_t address = 0;
    uint64_t size = 0;
    uint32_t flags = 0;
};

struct HeapInfo {
    uint64_t id = 0;
    size_t block_count = 0;
    uint64_t total_bytes = 0;
    std::vector<HeapBlock> blocks;
};

struct HandleInfo {
    uint64_t value = 0;
    uint32_t type_index = 0;
    std::string type;
    std::string name;
    uint32_t access = 0;
};

// TEB / PEB ------------------------------------------------------------------
// `expected_peb` (0 = unknown) disambiguates the WOW64 case, where a thread has
// both a 32-bit and a 64-bit TEB and only one of them points at the PEB that
// read_peb validated.
bool read_teb(HANDLE proc, HANDLE thread, bool is32, TebInfo& out, std::string& err,
              uint64_t expected_peb = 0);
bool read_peb(HANDLE proc, bool is32, PebInfo& out, std::string& err);

// Heaps (toolhelp, works on another process) ---------------------------------
bool enum_heaps(uint32_t pid, std::vector<HeapInfo>& out, size_t max_blocks_per_heap,
                std::string& err);

// Handles (system wide table, filtered to one process). `type_filter` is
// applied while scanning so the `max` cap counts matching entries only.
bool enum_handles(uint32_t pid, const std::string& type_filter, std::vector<HandleInfo>& out,
                  size_t max, std::string& err);

Json teb_to_json(const TebInfo& t);
Json peb_to_json(const PebInfo& p);

}  // namespace aj
