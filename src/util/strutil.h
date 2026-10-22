#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace aj {

std::string fmt(const char* f, ...);

std::string trim(const std::string& s);
std::string to_lower(std::string s);
std::vector<std::string> split_ws(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);

// simple glob match: '*' matches any run, '?' matches one char (case sensitive)
bool wild_match(const std::string& s, const std::string& pat);

// Accepts 0x1234, 1234h, 1234 decimal, and 0n1234 (decimal).
bool parse_u64(const std::string& s, uint64_t& out);

// "48 8B ?? 90" / "488B??90" -> bytes + wildcard mask (true = must match)
bool parse_pattern(const std::string& s, std::vector<uint8_t>& bytes,
                   std::vector<bool>& mask);

std::string bytes_to_hex(const uint8_t* data, size_t n);
std::string bytes_to_hex(const std::vector<uint8_t>& v);

// UTF-8 <-> UTF-16 helpers for Win32 calls
std::wstring to_wide(const std::string& s);
std::string to_utf8(const std::wstring& s);

// "0x1234" style formatting used all over the text output
std::string hex8(uint64_t v);
std::string hex_no_prefix(uint64_t v);

}  // namespace aj
