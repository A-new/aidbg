#include "engine/pedump.h"

#include <cstring>

#include "engine/memory.h"
#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

namespace {

constexpr uint16_t kPe32 = 0x10B;
constexpr uint16_t kPe32Plus = 0x20B;
constexpr uint16_t kDynamicBase = 0x0040;

constexpr uint32_t kDirImport = 1;
constexpr uint32_t kDirIat = 12;
constexpr uint32_t kDirReloc = 5;
constexpr uint16_t kRelocHighLow = 3;   // 32-bit relocation
constexpr uint16_t kRelocDir64 = 10;    // 64-bit relocation
constexpr uint64_t kOrdinalFlag64 = 0x8000000000000000ull;
constexpr uint32_t kOrdinalFlag32 = 0x80000000u;

struct SectionRaw {
    std::string name;
    uint32_t vsize = 0;
    uint32_t va = 0;
    uint32_t raw_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t chars = 0;
};

uint64_t align_up(uint64_t v, uint64_t a) { return a ? ((v + a - 1) / a) * a : v; }

bool read_mem(HANDLE proc, uint64_t addr, void* buf, size_t n, std::string& err) {
    size_t got = 0;
    return read_memory(proc, addr, buf, n, err, &got) && got == n;
}

// The output image: every section's initialized bytes in memory, so the
// repairs below can patch them before anything reaches the file.
struct OutImage {
    struct Sec {
        std::string name;
        uint32_t va = 0;
        uint32_t vsize = 0;
        uint32_t raw_size = 0;  // aligned output size
        uint32_t raw_ptr = 0;
        uint32_t chars = 0;
        std::vector<uint8_t> data;
    };
    std::vector<Sec> secs;
    uint64_t base = 0;      // runtime load address
    uint64_t image_size = 0;

    uint32_t ptr = 8;

    uint8_t* at(uint32_t rva, uint32_t n) {
        for (auto& s : secs) {
            if (rva >= s.va && rva + n <= s.va + s.data.size()) return s.data.data() + (rva - s.va);
        }
        return nullptr;
    }
    bool read_ptr(uint32_t rva, uint64_t& v) {
        uint8_t* p = at(rva, ptr);
        if (!p) return false;
        v = 0;
        std::memcpy(&v, p, ptr);
        return true;
    }
    bool write_ptr(uint32_t rva, uint64_t v) {
        uint8_t* p = at(rva, ptr);
        if (!p) return false;
        std::memcpy(p, &v, ptr);
        return true;
    }
    uint32_t virtual_end() const {
        uint32_t end = 0;
        for (auto& s : secs) {
            uint32_t e = s.va + (s.vsize ? s.vsize : s.raw_size);
            if (e > end) end = e;
        }
        return end;
    }
};

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

}  // namespace

bool dump_pe(HANDLE proc, uint64_t base, const std::string& path, const DumpOptions& opts,
             Json& report, std::string& err) {
    report = Json::obj();

    // ---- parse the in-memory PE headers ---------------------------------
    uint8_t dos[0x40];
    if (!read_mem(proc, base, dos, sizeof(dos), err)) {
        err = "cannot read the DOS header from the target";
        return false;
    }
    if (dos[0] != 'M' || dos[1] != 'Z') {
        err = "target is not a PE image (no MZ signature)";
        return false;
    }
    uint32_t lfanew = *(uint32_t*)(dos + 0x3C);
    if (lfanew > 0x1000) {
        err = "bad e_lfanew";
        return false;
    }

    // signature + file header + enough of the optional header
    std::vector<uint8_t> hdr(4 + 20 + 0x70);
    if (!read_mem(proc, base + lfanew, hdr.data(), hdr.size(), err)) {
        err = "cannot read the NT headers";
        return false;
    }
    if (std::memcmp(hdr.data(), "PE\0\0", 4) != 0) {
        err = "no PE signature";
        return false;
    }
    uint8_t* fh = hdr.data() + 4;
    uint16_t num_sections = *(uint16_t*)(fh + 2);
    uint16_t opt_size = *(uint16_t*)(fh + 16);
    uint8_t* opt = hdr.data() + 24;
    uint16_t magic = *(uint16_t*)opt;
    bool is64 = (magic == kPe32Plus);
    if (!is64 && magic != kPe32) {
        err = "unknown optional header format";
        return false;
    }

    // SectionAlignment/FileAlignment sit at +0x20/+0x24 in BOTH optional
    // header formats (+0x30/+0x34 is Subsystem/Win32Version - reading those
    // made every alignment computation silently use 6.0 and 0)
    uint32_t sect_align = *(uint32_t*)(opt + 0x20);
    uint32_t file_align = *(uint32_t*)(opt + 0x24);
    uint32_t size_image = *(uint32_t*)(opt + 0x38);
    uint32_t size_headers = *(uint32_t*)(opt + 0x3C);
    if (!file_align) file_align = 0x200;
    if (!sect_align) sect_align = 0x1000;
    if (!num_sections || num_sections > 96) {
        err = "implausible section count";
        return false;
    }
    if (!size_image) {
        err = "implausible SizeOfImage";
        return false;
    }
    // The output header buffer is allocated from the target's SizeOfHeaders
    // and then patched at target-controlled offsets (e_lfanew, opt_size,
    // section table). Validate the whole range first: a packed sample that
    // shrinks SizeOfHeaders in memory used to drive an out-of-bounds heap
    // write here.
    const uint64_t kMaxHeaders = 0x1000000;  // 16 MiB
    if (size_headers < 0x40 || size_headers > kMaxHeaders) {
        err = "implausible SizeOfHeaders";
        return false;
    }
    if (opt_size < 0x48) {
        err = "implausible SizeOfOptionalHeader";
        return false;
    }
    const uint64_t min_header_end = (uint64_t)lfanew + 24 + 0x48;
    if ((uint64_t)size_headers < min_header_end) {
        err = "header area too small for the optional header";
        return false;
    }

    // ---- section table ---------------------------------------------------
    size_t sect_off = lfanew + 4 + 20 + opt_size;
    if ((uint64_t)sect_off + (uint64_t)num_sections * 40 > size_headers) {
        err = "section table lies outside SizeOfHeaders";
        return false;
    }
    std::vector<uint8_t> sect_buf((size_t)num_sections * 40);
    if (!read_mem(proc, base + sect_off, sect_buf.data(), sect_buf.size(), err)) {
        err = "cannot read the section table";
        return false;
    }
    std::vector<SectionRaw> sections(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const uint8_t* s = sect_buf.data() + (size_t)i * 40;
        SectionRaw& r = sections[i];
        char nm[9] = {0};
        std::memcpy(nm, s, 8);
        r.name = nm;
        r.vsize = *(uint32_t*)(s + 8);
        r.va = *(uint32_t*)(s + 12);
        r.raw_size = *(uint32_t*)(s + 16);
        r.raw_ptr = *(uint32_t*)(s + 20);
        r.chars = *(uint32_t*)(s + 36);
    }

    // ---- header buffer we will write ------------------------------------
    std::vector<uint8_t> header(size_headers);
    if (!read_mem(proc, base, header.data(), size_headers, err)) {
        err = "cannot read the header area";
        return false;
    }
    // data directories live inside the optional header. The count field sits
    // past the minimal header size validated above, so bound it before reading
    // (a malformed SizeOfHeaders could otherwise read out of the buffer).
    const size_t num_dirs =
        (lfanew + 24 + (is64 ? 0x6C : 0x5C) + 2 <= header.size())
            ? (size_t) * (uint16_t*)(header.data() + lfanew + 24 + (is64 ? 0x6C : 0x5C))
            : 0;
    const size_t dirs_off = lfanew + 24 + (is64 ? 0x70 : 0x60);
    auto dir_at = [&](size_t index) -> uint8_t* {
        if (index >= num_dirs) return nullptr;
        size_t off = dirs_off + index * 8;
        if (off + 8 > header.size()) return nullptr;
        return header.data() + off;
    };
    uint32_t imp_rva = 0, imp_size = 0, iat_rva = 0, iat_size = 0, rel_rva = 0, rel_size = 0;
    if (uint8_t* d = dir_at(kDirImport)) {
        imp_rva = *(uint32_t*)d;
        imp_size = *(uint32_t*)(d + 4);
    }
    if (uint8_t* d = dir_at(kDirIat)) {
        iat_rva = *(uint32_t*)d;
        iat_size = *(uint32_t*)(d + 4);
    }
    if (uint8_t* d = dir_at(kDirReloc)) {
        rel_rva = *(uint32_t*)d;
        rel_size = *(uint32_t*)(d + 4);
    }

    // ---- output layout --------------------------------------------------
    // Mirror mode keeps PointerToRawData == VirtualAddress, so the file looks
    // exactly like the memory image: no arithmetic to get wrong, and any new
    // section the packer created is preserved. Compact packs them tightly.
    uint64_t next_raw = align_up(size_headers, file_align);
    for (auto& s : sections) {
        uint64_t need = s.vsize ? s.vsize : s.raw_size;
        // A section cannot legitimately be much larger than the image it is
        // part of; otherwise a crafted header makes us write a multi-GB file.
        if (need > (uint64_t)size_image + 0x1000000) {
            err = "implausible section size";
            return false;
        }
        uint64_t raw_size = align_up(need, file_align);
        if (opts.compact) {
            s.raw_ptr = (uint32_t)next_raw;
            next_raw += raw_size;
        } else {
            uint64_t p = align_up(s.va ? s.va : next_raw, file_align);
            s.raw_ptr = (uint32_t)p;
            next_raw = p + raw_size;
        }
        if (next_raw > 0xFFFFFFFFull) {
            err = "output image exceeds the 4 GB PE offset limit";
            return false;
        }
        s.raw_size = (uint32_t)raw_size;
    }
    uint64_t total = next_raw;
    if (total < size_headers) total = size_headers;

    // ---- read every section into memory ----------------------------------
    OutImage img;
    img.base = base;
    img.image_size = size_image;
    img.ptr = is64 ? 8 : 4;
    for (auto& s : sections) {
        OutImage::Sec o;
        o.name = s.name;
        o.va = s.va;
        o.vsize = s.vsize;
        o.raw_size = s.raw_size;
        o.raw_ptr = s.raw_ptr;
        o.chars = s.chars;
        uint32_t want = s.vsize ? s.vsize : s.raw_size;
        if (want > s.raw_size) want = s.raw_size;
        o.data.resize(want);
        std::string e;
        if (want) {
            size_t got = 0;
            if (!read_memory(proc, base + s.va, o.data.data(), want, e, &got) || got == 0)
                o.data.clear();  // unreadable: zero-filled in the file
            else if (got < want)
                o.data.resize(got);
        }
        img.secs.push_back(std::move(o));
    }

    uint8_t* o = header.data() + lfanew + 24;
    uint8_t* fh_out = header.data() + lfanew + 4 + 2;  // NumberOfSections field

    // ---- order note -------------------------------------------------------
    // The import scan below resolves runtime pointers, so it MUST run before
    // the relocation repair rewrites them into preferred-base form (the two
    // used to run the other way around, which silently disabled the import
    // rebuild for keepbase dumps with a non-zero slide).

    // ---- import table repair ---------------------------------------------
    Json imp_report = Json::obj();
    uint64_t new_va = align_up(img.virtual_end(), sect_align);
    if (opts.fix_iat && opts.resolve_import) {
        // Only rebuild when the original table cannot work: a still-intact
        // descriptor chain (unpacked targets, or dumps taken before the
        // loader destroyed anything) resolves names on its own, and the
        // loader is far happier with it than with any table we synthesize.
        // The rebuild is for the packed case, where the directory is gone or
        // its thunks point outside the image.
        bool orig_ok = false;
        if (imp_rva) {
            orig_ok = true;
            uint32_t cur = imp_rva;
            for (int d = 0; d < 512 && orig_ok; ++d) {
                uint8_t* p = img.at(cur, 20);
                if (!p) {
                    orig_ok = false;
                    break;
                }
                uint32_t oft = *(uint32_t*)p, namerva = *(uint32_t*)(p + 12),
                         ft = *(uint32_t*)(p + 16);
                if (!oft && !ft) break;  // terminator: the chain is complete
                if (!namerva || !img.at(namerva, 2)) orig_ok = false;
                uint32_t walk = oft ? oft : ft;
                if (orig_ok) {
                    for (int k = 0; k < 65536; ++k) {
                        uint8_t* t = img.at(walk + (uint32_t)(k * img.ptr), img.ptr);
                        if (!t) {
                            orig_ok = false;
                            break;
                        }
                        uint64_t v = 0;
                        std::memcpy(&v, t, img.ptr);
                        if (!v) break;  // end of this thunk array
                        if (!(v & (is64 ? kOrdinalFlag64 : kOrdinalFlag32)) &&
                            !img.at((uint32_t)v, 2))
                            orig_ok = false;
                        if (!orig_ok) break;
                    }
                }
                cur += 20;
            }
        }
        if (orig_ok) {
            imp_report.set_str("note",
                               "original import table intact; kept as dumped (rebuild skipped)");
        } else {
        struct Segment {
            uint32_t thunk_rva;      // first original slot (FirstThunk target)
            std::string module;
            std::vector<std::pair<std::string, uint64_t>> names;  // name / ordinal
        };
        std::vector<Segment> segments;
        size_t skipped_singles = 0;
        Segment cur;
        bool in_run = false;
        for (auto& s : img.secs) {
            for (size_t off = 0; off + img.ptr <= s.data.size(); off += img.ptr) {
                uint64_t v = 0;
                std::memcpy(&v, s.data.data() + off, img.ptr);
                std::string mod, fn;
                uint64_t ord = 0;
                const uint32_t rva = s.va + (uint32_t)off;
                if (opts.resolve_import(v, mod, fn, ord)) {
                    if (in_run && (mod != cur.module || rva != cur.thunk_rva +
                                                          (uint32_t)(cur.names.size() * img.ptr))) {
                        // module change or a hole: close the run
                        if (cur.names.size() > 1 ||
                            (cur.thunk_rva >= imp_rva && cur.thunk_rva < imp_rva + imp_size) ||
                            (cur.thunk_rva >= iat_rva && cur.thunk_rva < iat_rva + iat_size))
                            segments.push_back(std::move(cur));
                        else
                            ++skipped_singles;
                        cur = Segment{};
                        in_run = false;
                    }
                    if (!in_run) {
                        cur = Segment{};
                        cur.thunk_rva = rva;
                        cur.module = mod;
                        in_run = true;
                    }
                    cur.names.push_back({fn, ord});
                } else if (in_run) {
                    if (cur.names.size() > 1 ||
                        (cur.thunk_rva >= imp_rva && cur.thunk_rva < imp_rva + imp_size) ||
                        (cur.thunk_rva >= iat_rva && cur.thunk_rva < iat_rva + iat_size))
                        segments.push_back(std::move(cur));
                    else
                        ++skipped_singles;
                    cur = Segment{};
                    in_run = false;
                }
            }
        }
        if (in_run) {
            if (cur.names.size() > 1 ||
                (cur.thunk_rva >= imp_rva && cur.thunk_rva < imp_rva + imp_size) ||
                (cur.thunk_rva >= iat_rva && cur.thunk_rva < iat_rva + iat_size))
                segments.push_back(std::move(cur));
            else
                ++skipped_singles;
        }

        size_t total_thunks = 0;
        for (auto& sg : segments) total_thunks += sg.names.size();
        if (!segments.empty() && total_thunks <= 65536 && segments.size() <= 512) {
            // assemble the appended section: descriptors, module names,
            // OriginalFirstThunk arrays, hint/name entries
            std::vector<uint8_t> blob;
            auto align8 = [&] {
                while (blob.size() % 8) blob.push_back(0);
            };
            // descriptors first (n + 1 terminators), fixed 20 bytes each
            const size_t desc_count = segments.size() + 1;
            blob.resize(desc_count * 20, 0);
            std::vector<uint32_t> name_rvas(segments.size(), 0);
            std::vector<uint32_t> oft_rvas(segments.size(), 0);
            std::vector<std::vector<uint32_t>> hint_rvas(segments.size());
            // module name strings
            for (size_t i = 0; i < segments.size(); ++i) {
                align8();
                name_rvas[i] = (uint32_t)new_va + (uint32_t)blob.size();
                for (char c : segments[i].module) blob.push_back((uint8_t)c);
                blob.push_back(0);
            }
            // OFT arrays
            for (size_t i = 0; i < segments.size(); ++i) {
                align8();
                oft_rvas[i] = (uint32_t)new_va + (uint32_t)blob.size();
                hint_rvas[i].resize(segments[i].names.size(), 0);
                blob.resize(blob.size() + (segments[i].names.size() + 1) * img.ptr, 0);
            }
            // hint/name entries
            for (size_t i = 0; i < segments.size(); ++i) {
                for (size_t k = 0; k < segments[i].names.size(); ++k) {
                    align8();
                    hint_rvas[i][k] = (uint32_t)new_va + (uint32_t)blob.size();
                    put_u16(blob, 0);  // hint
                    for (char c : segments[i].names[k].first) blob.push_back((uint8_t)c);
                    blob.push_back(0);
                }
            }
            // fill the descriptors and OFT arrays (written in place; the
            // arrays above were allocated zeroed)
            for (size_t i = 0; i < segments.size(); ++i) {
                uint32_t* desc = (uint32_t*)(blob.data() + i * 20);
                desc[0] = oft_rvas[i];            // OriginalFirstThunk
                desc[1] = 0;                      // TimeDateStamp
                desc[2] = 0;                      // ForwarderChain
                desc[3] = name_rvas[i];           // Name
                desc[4] = segments[i].thunk_rva;  // FirstThunk -> original slots
                uint8_t* oft = blob.data() + (oft_rvas[i] - (uint32_t)new_va);
                for (size_t k = 0; k < segments[i].names.size(); ++k) {
                    uint64_t entry;
                    if (segments[i].names[k].first.empty())
                        entry = (is64 ? kOrdinalFlag64 : kOrdinalFlag32) |
                                segments[i].names[k].second;
                    else
                        entry = hint_rvas[i][k];
                    std::memcpy(oft + k * img.ptr, &entry, img.ptr);
                }
                // trailing zero entry already zeroed
            }

            // room for one more section header (and a 32-bit raw offset)?
            if ((uint64_t)sect_off + (uint64_t)(num_sections + 1) * 40 > size_headers ||
                new_va + align_up(blob.size(), file_align) > 0xFFFFFFFFull) {
                imp_report.set_str(
                    "note", "no room in SizeOfHeaders for the repair section; imports left as "
                            "dumped (raw pointers)");
            } else {
                uint32_t blob_raw_size = (uint32_t)align_up(blob.size(), file_align);
                uint32_t new_raw = opts.compact ? (uint32_t)align_up(total, file_align)
                                                : (uint32_t)new_va;
                // section table entry
                uint8_t* sh = header.data() + sect_off + (size_t)num_sections * 40;
                std::memset(sh, 0, 40);
                std::memcpy(sh, "aidbgIAT", 8);
                *(uint32_t*)(sh + 8) = (uint32_t)blob.size();          // VirtualSize
                *(uint32_t*)(sh + 12) = (uint32_t)new_va;              // VirtualAddress
                *(uint32_t*)(sh + 16) = blob_raw_size;                 // SizeOfRawData
                *(uint32_t*)(sh + 20) = new_raw;                       // PointerToRawData
                *(uint32_t*)(sh + 36) = 0xC0000040;                    // R+W, initialized
                *(uint16_t*)fh_out = (uint16_t)(num_sections + 1);     // NumberOfSections
                *(uint32_t*)(o + 0x38) =                               // SizeOfImage
                    (uint32_t)align_up(new_va + blob.size(), sect_align);

                if (uint8_t* d = dir_at(kDirImport)) {
                    *(uint32_t*)d = (uint32_t)new_va;  // the descriptor array
                    *(uint32_t*)(d + 4) = (uint32_t)(desc_count * 20);
                }
                if (uint8_t* d = dir_at(kDirIat)) {
                    *(uint32_t*)d = 0;  // stale IAT range: the loader refills
                    *(uint32_t*)(d + 4) = 0;
                }

                // hand the section to the writer below
                OutImage::Sec fix;
                fix.name = "aidbgIAT";
                fix.va = (uint32_t)new_va;
                fix.vsize = (uint32_t)blob.size();
                fix.raw_size = blob_raw_size;
                fix.raw_ptr = new_raw;
                fix.chars = 0xC0000040;
                fix.data = std::move(blob);
                img.secs.push_back(std::move(fix));
                if (fix.raw_ptr + fix.raw_size > total) total = fix.raw_ptr + fix.raw_size;

                Json segs = Json::arr();
                for (auto& sg : segments) {
                    Json j = Json::obj();
                    j.set_str("module", sg.module);
                    j.set_u("thunks", sg.names.size());
                    j.set_hex("first_thunk", sg.thunk_rva);
                    segs.push(std::move(j));
                }
                imp_report.set("modules", segs);
                imp_report.set_u("module_count", segments.size());
                imp_report.set_u("thunks", total_thunks);
                imp_report.set_u("singles_skipped", skipped_singles);
                imp_report.set_hex("section_rva", new_va);
            }
        } else if (!segments.empty()) {
            imp_report.set_str("note",
                               fmt("import repair too large (%llu thunks over %zu modules); "
                                   "imports left as dumped",
                                   (unsigned long long)total_thunks, segments.size()));
        } else {
            imp_report.set_str("note", "no import-like pointer runs found; imports left as dumped");
            imp_report.set_u("singles_skipped", skipped_singles);
        }
        }  // !orig_ok: the rebuild path
    }
    if (imp_report.size()) report.set("imports", std::move(imp_report));

    // ---- relocation repair ------------------------------------------------
    // keepbase restores the preferred ImageBase and subtracts the relocation
    // slide from every base relocation the loader applied, so the dump is a
    // normally relocatable image again. Without relocation info the best we
    // can do is pin the file to the runtime base (and say so).
    Json reloc_report = Json::obj();
    if (!opts.pin_image_base) {
        uint64_t slide = opts.preferred_base ? (base - opts.preferred_base) : 0;
        bool restored = false;
        size_t fixed = 0, scanned = 0;
        if (slide != 0 && rel_rva && rel_size) {
            // walk the .reloc blocks straight from the captured image
            for (uint32_t off = 0; off + 8 <= rel_size;) {
                uint8_t* blk = img.at(rel_rva + off, 8);
                if (!blk) break;
                uint32_t page_rva = *(uint32_t*)blk;
                uint32_t block_size = *(uint32_t*)(blk + 4);
                if (block_size < 8 || block_size > rel_size - off) break;
                for (uint32_t e = 8; e + 2 <= block_size; e += 2) {
                    uint16_t entry = *(uint16_t*)(blk + e);
                    uint16_t type = entry >> 12;
                    uint32_t ofs = entry & 0xFFF;
                    // Only the pointer-width base relocations can be
                    // un-applied here: ABSOLUTE (0) entries are padding and
                    // HIGHADJ pairs need their companion entry handled.
                    // Offset 0 within a page is a legitimate target.
                    if (type != (is64 ? kRelocDir64 : kRelocHighLow)) continue;
                    uint32_t rva = page_rva + ofs;
                    if (rva + img.ptr > size_image) continue;
                    uint64_t v = 0;
                    if (!img.read_ptr(rva, v)) continue;
                    ++scanned;
                    if (v >= base && v < base + size_image) {
                        img.write_ptr(rva, v - slide);
                        ++fixed;
                    }
                }
                off += block_size;
            }
            if (fixed || scanned) {
                // ImageBase back to the preferred value the relocations assume
                if (is64)
                    *(uint64_t*)(o + 0x18) = opts.preferred_base;
                else
                    *(uint32_t*)(o + 0x1C) = (uint32_t)opts.preferred_base;
                restored = true;
            }
        }
        if (restored) {
            reloc_report.set_hex("slide", slide);
            reloc_report.set_u("entries_scanned", scanned);
            reloc_report.set_u("entries_unrelocated", fixed);
            reloc_report.set_bool("image_base_restored", true);
            reloc_report.set_hex("image_base", opts.preferred_base);
        } else {
            // no relocation info (stripped by the packer) or slide == 0:
            // make sure the file never gets relocated over already-relocated
            // values - pin it to wherever it currently sits
            uint16_t dllch = *(uint16_t*)(o + 0x46);
            *(uint16_t*)(o + 0x46) = (uint16_t)(dllch & ~kDynamicBase);
            if (is64)
                *(uint64_t*)(o + 0x18) = base;
            else
                *(uint32_t*)(o + 0x1C) = (uint32_t)base;
            reloc_report.set_bool("image_base_restored", false);
            reloc_report.set_str(
                "note", "no usable relocation table (or already at its preferred base); the "
                        "dump is pinned to the runtime base and ASLR is cleared");
        }
    }
    if (reloc_report.size()) report.set("relocation", std::move(reloc_report));

    // ---- header patches that apply to every mode --------------------------
    if (opts.pin_image_base) {
        if (is64)
            *(uint64_t*)(o + 0x18) = base;
        else
            *(uint32_t*)(o + 0x1C) = (uint32_t)base;
        // a dump must load exactly where it was captured
        uint16_t dllch = *(uint16_t*)(o + 0x46);
        *(uint16_t*)(o + 0x46) = (uint16_t)(dllch & ~kDynamicBase);
    }
    if (opts.entry_point) {
        if (opts.entry_point >= base && opts.entry_point < base + size_image)
            *(uint32_t*)(o + 0x10) = (uint32_t)(opts.entry_point - base);
        else {
            err = "the requested entry point is outside the image";
            return false;
        }
    }
    // SizeOfRawData / PointerToRawData must reflect the layout we just chose
    for (uint16_t i = 0; i < num_sections; ++i) {
        uint8_t* s = header.data() + sect_off + (size_t)i * 40;
        *(uint32_t*)(s + 16) = sections[i].raw_size;
        *(uint32_t*)(s + 20) = sections[i].raw_ptr;
    }

    // ---- write the file --------------------------------------------------
    HANDLE h = CreateFileW(to_wide(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = fmt("cannot create '%s': %s", path.c_str(), last_error_text().c_str());
        return false;
    }
    auto close_fail = [&](const std::string& m) {
        err = m;
        CloseHandle(h);
        DeleteFileW(to_wide(path).c_str());
        return false;
    };

    DWORD wrote = 0;
    if (!WriteFile(h, header.data(), (DWORD)header.size(), &wrote, nullptr))
        return close_fail("cannot write the headers");
    // pad to the first section's raw offset
    if (!img.secs.empty() && img.secs[0].raw_ptr > header.size()) {
        std::vector<uint8_t> pad(img.secs[0].raw_ptr - header.size(), 0);
        if (!WriteFile(h, pad.data(), (DWORD)pad.size(), &wrote, nullptr))
            return close_fail("cannot write the header padding");
    }

    Json sect_json = Json::arr();
    // WriteFile appends, but each section declares its own PointerToRawData, so
    // the gaps between sections have to be filled or the loader sees a file
    // that is shorter than its own section table claims.
    auto pad_to = [&](uint64_t offset) {
        LARGE_INTEGER cur;
        SetFilePointerEx(h, {0, 0}, &cur, FILE_CURRENT);
        if ((uint64_t)cur.QuadPart >= offset) return true;
        std::vector<uint8_t> z((size_t)(offset - (uint64_t)cur.QuadPart), 0);
        DWORD w = 0;
        return WriteFile(h, z.data(), (DWORD)z.size(), &w, nullptr) != FALSE;
    };

    for (auto& s : img.secs) {
        if (!pad_to(s.raw_ptr)) return close_fail("cannot pad before section " + s.name);

        uint64_t want = s.data.size();

        if (want) {
            DWORD w = 0;
            if (!WriteFile(h, s.data.data(), (DWORD)want, &w, nullptr))
                return close_fail("cannot write section " + s.name);
        }
        // zero-fill the slack so the section's declared raw size is honoured
        uint64_t slack = s.raw_size > want ? s.raw_size - want : 0;
        if (slack && !pad_to(s.raw_ptr + s.raw_size))
            return close_fail("cannot pad section " + s.name);

        Json sj = Json::obj();
        sj.set_str("name", s.name);
        sj.set_hex("virtual_address", s.va);
        sj.set_u("virtual_size", s.vsize);
        sj.set_hex("raw_offset", s.raw_ptr);
        sj.set_u("raw_size", s.raw_size);
        sj.set_u("bytes_copied", want);
        sect_json.push(std::move(sj));
    }
    // make the file end exactly where the section table says it does
    if (!pad_to(total)) return close_fail("cannot pad the file to its final size");

    LARGE_INTEGER sz;
    GetFileSizeEx(h, &sz);
    CloseHandle(h);

    report.set_str("path", path);
    report.set_hex("base", base);
    report.set_u("file_size", (uint64_t)sz.QuadPart);
    report.set_u("size_of_image", size_image);
    report.set_u("sections", *(uint16_t*)fh_out);
    report.set_bool("pinned_image_base", opts.pin_image_base);
    if (opts.entry_point) report.set_hex("entry_point", opts.entry_point);
    report.set("section_table", sect_json);
    return true;
}

}  // namespace aj
