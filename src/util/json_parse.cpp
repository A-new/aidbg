#include "util/json_parse.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "util/strutil.h"

namespace aj {
namespace {

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    bool parse(Json& out, std::string& err) {
        err_.clear();
        skip_ws();
        if (!parse_value(out)) {
            if (err_.empty()) err_ = "unexpected end of input";
            err = err_;
            return false;
        }
        skip_ws();
        if (pos_ != s_.size()) {
            err = "trailing data after JSON value";
            return false;
        }
        return true;
    }

private:
    void skip_ws() {
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                ++pos_;
            else
                break;
        }
    }

    bool eof() const { return pos_ >= s_.size(); }
    char peek() const { return pos_ < s_.size() ? s_[pos_] : '\0'; }
    bool consume(char c) {
        if (peek() == c) {
            ++pos_;
            return true;
        }
        return false;
    }
    void fail(const std::string& m) {
        if (err_.empty()) err_ = fmt("offset %zu: %s", pos_, m.c_str());
    }

    bool parse_value(Json& out) {
        skip_ws();
        if (eof()) {
            fail("unexpected end of input");
            return false;
        }
        char c = peek();
        switch (c) {
            case '{': return parse_object(out);
            case '[': return parse_array(out);
            case '"': {
                std::string v;
                if (!parse_string(v)) return false;
                out = Json::s(v);
                return true;
            }
            case 't': return parse_literal("true", Json::boolean(true), out);
            case 'f': return parse_literal("false", Json::boolean(false), out);
            case 'n': return parse_literal("null", Json::null(), out);
            default: return parse_number(out);
        }
    }

    bool parse_literal(const char* lit, Json value, Json& out) {
        size_t n = std::strlen(lit);
        if (s_.compare(pos_, n, lit) != 0) {
            fail(std::string("invalid literal, expected ") + lit);
            return false;
        }
        pos_ += n;
        out = std::move(value);
        return true;
    }

    bool parse_number(Json& out) {
        size_t start = pos_;
        if (peek() == '-') ++pos_;
        while (!eof() && (std::isdigit((unsigned char)peek()) || peek() == '.' || peek() == 'e' ||
                          peek() == 'E' || peek() == '+' || peek() == '-'))
            ++pos_;
        if (pos_ == start) {
            fail("invalid value");
            return false;
        }
        std::string tok = s_.substr(start, pos_ - start);
        bool is_float = tok.find_first_of(".eE") != std::string::npos;
        if (is_float) {
            out = Json::d(std::strtod(tok.c_str(), nullptr));
            return true;
        }
        // integer: pick the narrowest representation that round-trips
        errno = 0;
        if (tok[0] == '-') {
            long long v = std::strtoll(tok.c_str(), nullptr, 10);
            out = Json::i((int64_t)v);
        } else {
            unsigned long long v = std::strtoull(tok.c_str(), nullptr, 10);
            out = Json::u((uint64_t)v);
        }
        return true;
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out += (char)cp;
        } else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }

    bool parse_hex4(uint32_t& out) {
        if (pos_ + 4 > s_.size()) {
            fail("truncated \\u escape");
            return false;
        }
        out = 0;
        for (int i = 0; i < 4; ++i) {
            char c = s_[pos_ + i];
            uint32_t d;
            if (c >= '0' && c <= '9')
                d = (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                d = (uint32_t)(c - 'A' + 10);
            else {
                fail("bad hex digit in \\u escape");
                return false;
            }
            out = (out << 4) | d;
        }
        pos_ += 4;
        return true;
    }

    bool parse_string(std::string& out) {
        if (!consume('"')) {
            fail("expected string");
            return false;
        }
        out.clear();
        while (true) {
            if (eof()) {
                fail("unterminated string");
                return false;
            }
            char c = s_[pos_++];
            if (c == '"') return true;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (eof()) {
                fail("unterminated escape");
                return false;
            }
            char e = s_[pos_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp = 0;
                    if (!parse_hex4(cp)) return false;
                    // surrogate pair
                    if (cp >= 0xD800 && cp <= 0xDBFF && pos_ + 6 <= s_.size() &&
                        s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
                        pos_ += 2;
                        uint32_t lo = 0;
                        if (!parse_hex4(lo)) return false;
                        if (lo >= 0xDC00 && lo <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    append_utf8(out, cp);
                    break;
                }
                default:
                    fail("invalid escape sequence");
                    return false;
            }
        }
    }

    bool parse_array(Json& out) {
        if (!consume('[')) return false;
        out = Json::arr();
        skip_ws();
        if (consume(']')) return true;
        while (true) {
            Json v;
            if (!parse_value(v)) return false;
            out.push(std::move(v));
            skip_ws();
            if (consume(',')) {
                skip_ws();
                continue;
            }
            if (consume(']')) return true;
            fail("expected ',' or ']' in array");
            return false;
        }
    }

    bool parse_object(Json& out) {
        if (!consume('{')) return false;
        out = Json::obj();
        skip_ws();
        if (consume('}')) return true;
        while (true) {
            skip_ws();
            std::string key;
            if (!parse_string(key)) return false;
            skip_ws();
            if (!consume(':')) {
                fail("expected ':' in object");
                return false;
            }
            Json v;
            if (!parse_value(v)) return false;
            out.set(key, std::move(v));
            skip_ws();
            if (consume(',')) {
                skip_ws();
                continue;
            }
            if (consume('}')) return true;
            fail("expected ',' or '}' in object");
            return false;
        }
    }

    const std::string& s_;
    size_t pos_ = 0;
    std::string err_;
};

}  // namespace

bool json_parse(const std::string& text, Json& out, std::string& err) {
    Parser p(text);
    return p.parse(out, err);
}

}  // namespace aj
