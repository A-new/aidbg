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

    uint32_t entry_rva = *(uint32_t*)(opt + 0x10);
    uint64_t image_base = is64 ? *(uint64_t*)(opt + 0x18) : (uint64_t)*(uint32_t*)(opt + 0x1C);
    uint32_t sect_align = *(uint32_t*)(opt + 0x30);
    uint32_t file_align = *(uint32_t*)(opt + 0x34);
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

    // ---- section table ---------------------------------------------------
    size_t sect_off = lfanew + 4 + 20 + opt_size;
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

    // ---- output layout --------------------------------------------------
    // Mirror mode keeps PointerToRawData == VirtualAddress, so the file looks
    // exactly like the memory image: no arithmetic to get wrong, and any new
    // section the packer created is preserved. Compact packs them tightly.
    uint64_t next_raw = align_up(size_headers, file_align);
    for (auto& s : sections) {
        uint64_t need = s.vsize ? s.vsize : s.raw_size;
        uint64_t raw_size = align_up(need, file_align);
        if (opts.compact) {
            s.raw_ptr = (uint32_t)next_raw;
            next_raw += raw_size;
        } else {
            uint64_t p = align_up(s.va ? s.va : next_raw, file_align);
            s.raw_ptr = (uint32_t)p;
            next_raw = p + raw_size;
        }
        s.raw_size = (uint32_t)raw_size;
    }
    uint64_t total = next_raw;
    if (total < size_headers) total = size_headers;

    // ---- header buffer we will write ------------------------------------
    std::vector<uint8_t> header(size_headers);
    if (!read_mem(proc, base, header.data(), size_headers, err)) {
        err = "cannot read the header area";
        return false;
    }

    uint8_t* o = header.data() + lfanew + 24;
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
    if (sections.size() && sections[0].raw_ptr > header.size()) {
        std::vector<uint8_t> pad(sections[0].raw_ptr - header.size(), 0);
        if (!WriteFile(h, pad.data(), (DWORD)pad.size(), &wrote, nullptr))
            return close_fail("cannot write the header padding");
    }

    Json sect_json = Json::arr();
    std::vector<uint8_t> chunk(1 << 20);
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

    for (auto& s : sections) {
        if (!pad_to(s.raw_ptr))
            return close_fail("cannot pad before section " + s.name);

        uint64_t want = s.vsize ? s.vsize : s.raw_size;
        if (want > s.raw_size) want = s.raw_size;

        uint64_t copied = 0;
        while (copied < want) {
            size_t n = (size_t)(want - copied);
            if (n > chunk.size()) n = chunk.size();
            std::string e;
            size_t got = 0;
            if (!read_memory(proc, base + s.va + copied, chunk.data(), n, e, &got) || got == 0) {
                // leave the unread part zeroed; guard pages etc. can refuse
                std::memset(chunk.data(), 0, n);
            } else if (got < n) {
                std::memset(chunk.data() + got, 0, n - got);
            }
            DWORD w = 0;
            if (!WriteFile(h, chunk.data(), (DWORD)n, &w, nullptr))
                return close_fail("cannot write section " + s.name);
            copied += n;
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
    report.set_u("sections", num_sections);
    report.set_bool("pinned_image_base", opts.pin_image_base);
    if (opts.entry_point) report.set_hex("entry_point", opts.entry_point);
    report.set("section_table", sect_json);
    return true;
}

}  // namespace aj
