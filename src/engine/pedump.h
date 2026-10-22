#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

struct DumpOptions {
    // 0 = keep whatever the header says; set this to the original entry point
    // when dumping an unpacked image whose entry still points into the packer
    uint64_t entry_point = 0;
    // writes the real load address into ImageBase and clears DYNAMIC_BASE, so
    // the dumped file maps exactly where the memory image was
    bool pin_image_base = true;
    // lay sections out tightly instead of mirroring virtual addresses
    bool compact = false;
};

struct DumpSection {
    std::string name;
    uint64_t va = 0;
    uint64_t vsize = 0;
    uint64_t raw_offset = 0;
    uint64_t raw_size = 0;
    uint32_t characteristics = 0;
    uint64_t bytes_written = 0;
};

// Writes the target's in-memory image back out as a loadable PE file. This is
// the "dump" half of unpacking: after the packer has decrypted everything at
// runtime, the image is captured so it can be fixed up and run standalone.
bool dump_pe(HANDLE proc, uint64_t base, const std::string& path, const DumpOptions& opts,
             Json& report, std::string& err);

}  // namespace aj
