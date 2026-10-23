#pragma once
#include <windows.h>

#include <cstdint>
#include <functional>
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

    // ---- import table repair (Scylla-style "fix dump") --------------------
    // Rebuilds a loadable import table: data sections are scanned for runs of
    // pointers into module exports, and an appended section carries fresh
    // descriptors + hint/name arrays whose FirstThunk points back at the
    // original slots - the loader then resolves names into exactly the
    // locations the code reads.
    bool fix_iat = true;
    // Resolves a runtime pointer to module!function; false when the value is
    // not an export of any loaded module. `func` empty = ordinal import.
    std::function<bool(uint64_t value, std::string& module, std::string& func,
                       uint64_t& ordinal)>
        resolve_import;

    // ---- relocation repair (keepbase mode) ---------------------------------
    // The PE ImageBase as it was BEFORE the loader relocated the image. When
    // known (a loaded module's preferred base), keepbase mode restores it and
    // un-applies the relocation slide, producing a relocatable dump again.
    uint64_t preferred_base = 0;
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
// runtime, the image is captured, its import table rebuilt and its relocation
// state restored so the file runs standalone.
bool dump_pe(HANDLE proc, uint64_t base, const std::string& path, const DumpOptions& opts,
             Json& report, std::string& err);

}  // namespace aj
