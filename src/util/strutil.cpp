#include "util/strutil.h"

#include <windows.h>

#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

namespace aj {

std::string fmt(const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    va_list ap2;
    va_copy(ap2, ap);
    int n = std::vsnprintf(nullptr, 0, f, ap);
    va_end(ap);
    if (n <= 0) {
        va_end(ap2);
        return {};
    }
    std::string out((size_t)n, '\0');
    std::vsnprintf(out.data(), out.size() + 1, f, ap2);
    va_end(ap2);
    return out;
}

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace((unsigned char)s[b])) ++b;
    while (e > b && std::isspace((unsigned char)s[e - 1])) --e;
    return s.substr(b, e - b);
}

std::string to_lower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quote = false;
    char q = 0;
    for (char c : s) {
        if (in_quote) {
            if (c == q) {
                in_quote = false;
            } else {
                cur += c;
            }
        } else if (c == '"' || c == '\'') {
            in_quote = true;
            q = c;
        } else if (std::isspace((unsigned char)c)) {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(cur);
    return out;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}
bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool wild_match(const std::string& s, const std::string& pat) {
    size_t si = 0, pi = 0, star = std::string::npos, ss = 0;
    while (si < s.size()) {
        if (pi < pat.size() && (pat[pi] == '?' || pat[pi] == s[si])) {
            ++si;
            ++pi;
        } else if (pi < pat.size() && pat[pi] == '*') {
            star = pi++;
            ss = si;
        } else if (star != std::string::npos) {
            pi = star + 1;
            si = ++ss;
        } else {
            return false;
        }
    }
    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}

bool parse_u64(const std::string& in, uint64_t& out) {
    std::string s = trim(in);
    if (s.empty()) return false;
    int base = 10;
    if (starts_with(s, "0x") || starts_with(s, "0X")) {
        base = 16;
        s = s.substr(2);
    } else if (starts_with(s, "0n")) {
        base = 10;
        s = s.substr(2);
    } else if (ends_with(s, "h") || ends_with(s, "H")) {
        base = 16;
        s = s.substr(0, s.size() - 1);
    } else if (!std::isdigit((unsigned char)s[0]) && s[0] != '-') {
        // bare hex like "7ff6aabb0000" is ambiguous -> reject, require 0x
        return false;
    }
    if (s.empty()) return false;
    for (char c : s) {
        if (base == 16 ? !std::isxdigit((unsigned char)c) : !std::isdigit((unsigned char)c))
            return false;
    }
    char* end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, base);
    if (!end || *end) return false;
    out = (uint64_t)v;
    return true;
}

bool parse_pattern(const std::string& s, std::vector<uint8_t>& bytes,
                   std::vector<bool>& mask) {
    bytes.clear();
    mask.clear();

    auto add_byte = [&](const std::string& t) -> bool {
        if (t == "??" || t == "?") {
            bytes.push_back(0);
            mask.push_back(false);
            return true;
        }
        std::string h = t;
        if (starts_with(h, "0x") || starts_with(h, "0X")) h = h.substr(2);
        if (h.size() == 1) h = "0" + h;
        if (h.size() != 2) return false;
        if (!std::isxdigit((unsigned char)h[0]) || !std::isxdigit((unsigned char)h[1]))
            return false;
        uint64_t v = 0;
        parse_u64("0x" + h, v);
        bytes.push_back((uint8_t)v);
        mask.push_back(true);
        return true;
    };

    // split into whitespace separated tokens
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : s) {
        if (std::isspace((unsigned char)c)) {
            if (!cur.empty()) {
                tokens.push_back(cur);
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) tokens.push_back(cur);
    if (tokens.empty()) return false;

    if (tokens.size() == 1) {
        // contiguous form: 488B??90
        const std::string& t = tokens[0];
        if ((t.size() % 2) != 0) return false;
        for (size_t i = 0; i < t.size(); i += 2) {
            if (!add_byte(t.substr(i, 2))) return false;
        }
    } else {
        // spaced form: 48 8B ?? 90 / 0x48 0x8B ?? 0x90
        for (const auto& t : tokens) {
            if (!add_byte(t)) return false;
        }
    }
    return !bytes.empty();
}

std::string bytes_to_hex(const uint8_t* data, size_t n) {
    std::string out;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) out += ' ';
        out += fmt("%02X", data[i]);
    }
    return out;
}
std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    return bytes_to_hex(v.data(), v.size());
}

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

std::string to_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::string hex8(uint64_t v) { return fmt("0x%llx", (unsigned long long)v); }
std::string hex_no_prefix(uint64_t v) { return fmt("%llx", (unsigned long long)v); }

}  // namespace aj
