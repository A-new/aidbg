#include "engine/patch.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <map>

#include "util/strutil.h"

namespace aj {

namespace {

bool overlaps(uint64_t a_start, size_t a_len, uint64_t b_start, size_t b_len) {
    return a_start < b_start + b_len && b_start < a_start + a_len;
}

// Reads one little-endian scalar out of a byte buffer.
template <typename T>
T rd(const std::vector<uint8_t>& b, size_t off) {
    T v = 0;
    if (off + sizeof(T) <= b.size()) std::memcpy(&v, b.data() + off, sizeof(T));
    return v;
}

bool read_whole_file(const std::wstring& path, std::vector<uint8_t>& out, std::string& err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "cannot open " + to_utf8(path);
        return false;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(h);
        err = "unreasonable file size";
        return false;
    }
    out.resize((size_t)sz.QuadPart);
    DWORD got = 0;
    BOOL okf = ReadFile(h, out.data(), (DWORD)out.size(), &got, nullptr);
    CloseHandle(h);
    if (!okf || got != out.size()) {
        err = "read failed";
        return false;
    }
    return true;
}

bool write_whole_file(const std::wstring& path, const std::vector<uint8_t>& data,
                      std::string& err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "cannot create " + to_utf8(path);
        return false;
    }
    DWORD put = 0;
    BOOL okf = WriteFile(h, data.data(), (DWORD)data.size(), &put, nullptr);
    CloseHandle(h);
    if (!okf || put != data.size()) {
        err = "write failed";
        return false;
    }
    return true;
}

}  // namespace

// ------------------------------------------------------------- PatchMgr

int PatchMgr::record(const std::string& module, uint64_t rva,
                     const std::vector<uint8_t>& original,
                     const std::vector<uint8_t>& patched) {
    // Merge into every overlapping record of the same module. Over the
    // overlap the incoming `original` already holds our patched bytes, so the
    // true original must come from the stored record; outside it the incoming
    // bytes were never edited and are genuine.
    for (auto& r : records_) {
        if (to_lower(r.module) != to_lower(module)) continue;
        if (!overlaps(r.rva, r.original.size(), rva, original.size())) continue;

        uint64_t start = std::min(r.rva, rva);
        uint64_t end = std::max(r.rva + r.original.size(), rva + (uint64_t)original.size());
        size_t len = (size_t)(end - start);
        std::vector<uint8_t> orig(len), cur(len);
        for (size_t i = 0; i < len; i++) {
            uint64_t x = start + i;
            bool in_old = x >= r.rva && x < r.rva + r.original.size();
            bool in_new = x >= rva && x < rva + original.size();
            // `original` prefers the stored bytes (the true pre-edit state),
            // `patched` prefers the incoming ones (the latest edit).
            orig[i] = in_old ? r.original[(size_t)(x - r.rva)]
                             : original[(size_t)(x - rva)];
            cur[i] = in_new ? patched[(size_t)(x - rva)]
                            : r.patched[(size_t)(x - r.rva)];
        }
        r.rva = start;
        r.original = std::move(orig);
        r.patched = std::move(cur);
        return r.id;
    }
    int id = next_id_++;
    records_.push_back({id, module, rva, original, patched});
    return id;
}

const PatchRecord* PatchMgr::find(int id) const {
    for (auto& r : records_)
        if (r.id == id) return &r;
    return nullptr;
}

bool PatchMgr::remove(int id) {
    for (auto it = records_.begin(); it != records_.end(); ++it) {
        if (it->id == id) {
            records_.erase(it);
            return true;
        }
    }
    return false;
}

void PatchMgr::clear() {
    records_.clear();
}

bool PatchMgr::by_module(const std::string& module, std::vector<const PatchRecord*>& out,
                         std::string& err) const {
    std::map<std::string, int> spanned;
    for (auto& r : records_) spanned[to_lower(r.module)]++;
    if (module.empty()) {
        if (spanned.size() > 1) {
            err = "patches span " + std::to_string(spanned.size()) +
                  " modules; bake one module at a time";
            return false;
        }
    } else if (spanned.count(to_lower(module)) == 0) {
        err = "no patches recorded for module " + module;
        return false;
    }
    for (auto& r : records_) {
        if (!module.empty() && to_lower(r.module) != to_lower(module)) continue;
        out.push_back(&r);
    }
    return true;
}

// ------------------------------------------------------------- file apply

// Section table entry offsets (IMAGE_SECTION_HEADER is 40 bytes).
struct SectionEntry {
    uint32_t va = 0;
    uint32_t raw_size = 0;
    uint32_t raw_ptr = 0;
};

bool patch_file(const std::string& src_path, const std::string& dst_path,
                const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& edits,
                Json& report, std::string& err) {
    std::vector<uint8_t> file;
    if (!read_whole_file(to_wide(src_path), file, err)) return false;

    // --- parse just enough PE header to map RVAs and find the checksum ---
    if (file.size() < sizeof(IMAGE_DOS_HEADER) || rd<uint16_t>(file, 0) != 0x5A4D) {
        err = "not a PE file (no MZ header): " + src_path;
        return false;
    }
    size_t nt = rd<uint32_t>(file, 0x3C);
    if (nt + 4 + sizeof(IMAGE_FILE_HEADER) > file.size() ||
        rd<uint32_t>(file, nt) != 0x00004550) {  // "PE\0\0"
        err = "bad PE signature";
        return false;
    }
    size_t fh = nt + 4;
    uint16_t nsec = rd<uint16_t>(file, fh + 2);
    uint16_t opt_size = rd<uint16_t>(file, fh + 16);
    size_t opt = fh + sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = rd<uint16_t>(file, opt);
    bool plus = (magic == 0x20B);  // PE32+
    size_t checksum_off = opt + (plus ? 112 : 64);
    uint32_t size_of_headers = rd<uint32_t>(file, opt + (plus ? 108 : 60));
    size_t sec0 = opt + opt_size;
    if (sec0 + (size_t)nsec * 40 > file.size()) {
        err = "section table outside the file";
        return false;
    }

    std::vector<SectionEntry> secs;
    for (uint16_t i = 0; i < nsec; i++) {
        size_t s = sec0 + (size_t)i * 40;
        SectionEntry e;
        e.va = rd<uint32_t>(file, s + 12);
        e.raw_size = rd<uint32_t>(file, s + 16);
        e.raw_ptr = rd<uint32_t>(file, s + 20);
        secs.push_back(e);
    }

    // --- map every RVA to a raw file offset before touching anything ---
    struct Planned {
        uint64_t rva;
        size_t offset;
        std::vector<uint8_t> bytes;
    };
    std::vector<Planned> planned;
    for (auto& [rva, bytes] : edits) {
        size_t off = 0;
        if (rva < size_of_headers) {
            off = (size_t)rva;  // header bytes map 1:1
        } else {
            bool found = false;
            for (auto& s : secs) {
                if (rva >= s.va && rva < (uint64_t)s.va + s.raw_size) {
                    off = s.raw_ptr + (size_t)(rva - s.va);
                    found = true;
                    break;
                }
            }
            if (!found) {
                err = "RVA " + hex8(rva) + " has no raw file mapping (virtual-only data)";
                return false;
            }
        }
        if (off + bytes.size() > file.size()) {
            err = "RVA " + hex8(rva) + " falls outside the file";
            return false;
        }
        planned.push_back({rva, off, bytes});
    }

    // --- apply and fix the checksum ---
    for (auto& p : planned) std::memcpy(file.data() + p.offset, p.bytes.data(), p.bytes.size());

    uint32_t sum_field = rd<uint32_t>(file, checksum_off);
    std::memset(file.data() + checksum_off, 0, 4);
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < file.size(); i += 2) sum += rd<uint16_t>(file, i);
    if (file.size() & 1) sum += file.back();
    sum += file.size();
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint32_t checksum = (uint32_t)sum;
    // a zero checksum in the original stays zero: the loader ignores the
    // field for plain EXEs, so rewriting it would be a needless diff
    if (sum_field != 0) std::memcpy(file.data() + checksum_off, &checksum, 4);

    if (!write_whole_file(to_wide(dst_path), file, err)) return false;

    Json applied = Json::arr();
    for (auto& p : planned) {
        Json j = Json::obj();
        j.set_hex("rva", p.rva);
        j.set_u("file_offset", p.offset);
        j.set_u("size", p.bytes.size());
        j.set_str("bytes", bytes_to_hex(p.bytes));
        applied.push(std::move(j));
    }
    report = Json::obj();
    report.set_str("source", src_path);
    report.set_str("file", dst_path);
    report.set("applied", std::move(applied));
    report.set_u("checksum", checksum);
    return true;
}

}  // namespace aj
