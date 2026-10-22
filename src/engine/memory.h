#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

struct MemRegion {
    uint64_t base = 0;
    size_t size = 0;
    DWORD protect = 0;
    DWORD state = 0;
    DWORD type = 0;
    std::string module;
};

bool read_memory(HANDLE proc, uint64_t addr, void* buf, size_t n, std::string& err,
                 size_t* got = nullptr);
bool write_memory(HANDLE proc, uint64_t addr, const void* buf, size_t n, std::string& err);
bool read_u64(HANDLE proc, uint64_t addr, uint64_t& out, std::string& err);
bool flush_icache(HANDLE proc, uint64_t addr, size_t n);

bool alloc_memory(HANDLE proc, size_t n, uint64_t& out, std::string& err, uint64_t hint = 0);
// Allocates within +/-2GB of `hint`, which is what RIP-relative references need.
bool alloc_memory_near(HANDLE proc, size_t n, uint64_t hint, uint64_t& out, std::string& err);
bool free_memory(HANDLE proc, uint64_t addr, std::string& err);
bool protect_memory(HANDLE proc, uint64_t addr, size_t n, DWORD prot, DWORD& old_prot,
                    std::string& err);

std::vector<MemRegion> query_regions(HANDLE proc, uint64_t start = 0, uint64_t end = 0);
bool region_at(HANDLE proc, uint64_t addr, MemRegion& out);

bool search_memory(HANDLE proc, uint64_t start, uint64_t end, const std::vector<uint8_t>& bytes,
                   const std::vector<bool>& mask, size_t max_hits, std::vector<uint64_t>& hits,
                   std::string& err);

std::string protect_text(DWORD p);
std::string state_text(DWORD s);
Json region_json(const MemRegion& r);

// hexdump rows: addr + 16 bytes + ascii
std::string hexdump(HANDLE proc, uint64_t addr, size_t n, std::string& err);

}  // namespace aj
