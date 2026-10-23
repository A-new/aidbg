#include "util/json.h"

#include <cmath>
#include <cstdio>

#include "util/strutil.h"

namespace aj {

Json Json::boolean(bool v) {
    Json j;
    j.type_ = Type::Bool;
    j.b_ = v;
    return j;
}
Json Json::i(int64_t v) {
    Json j;
    j.type_ = Type::Int;
    j.i_ = v;
    return j;
}
Json Json::u(uint64_t v) {
    Json j;
    // Always a real JSON number. Addresses that must stay exact go through
    // set_hex()/Json::hex(); turning large uints into "0x..." here broke
    // JSON-RPC ids and set_u("value_dec") (the field claimed to be decimal).
    j.type_ = Type::UInt;
    j.u_ = v;
    return j;
}
Json Json::d(double v) {
    Json j;
    j.type_ = Type::Double;
    j.d_ = v;
    return j;
}
Json Json::s(std::string v) {
    Json j;
    j.type_ = Type::Str;
    j.s_ = std::move(v);
    return j;
}
Json Json::hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return Json::s(buf);
}
Json Json::arr() {
    Json j;
    j.type_ = Type::Arr;
    return j;
}
Json Json::obj() {
    Json j;
    j.type_ = Type::Obj;
    return j;
}

Json& Json::set(const std::string& key, Json v) {
    if (type_ != Type::Obj) {
        type_ = Type::Obj;
        obj_.clear();
    }
    for (auto& kv : obj_) {
        if (kv.first == key) {
            kv.second = std::move(v);
            return *this;
        }
    }
    obj_.emplace_back(key, std::move(v));
    return *this;
}
Json& Json::set_str(const std::string& key, const std::string& v) { return set(key, Json::s(v)); }
Json& Json::set_hex(const std::string& key, uint64_t v) { return set(key, Json::hex(v)); }
Json& Json::set_u(const std::string& key, uint64_t v) { return set(key, Json::u(v)); }
Json& Json::set_i(const std::string& key, int64_t v) { return set(key, Json::i(v)); }
Json& Json::set_d(const std::string& key, double v) { return set(key, Json::d(v)); }
Json& Json::set_bool(const std::string& key, bool v) { return set(key, Json::boolean(v)); }

bool Json::has(const std::string& key) const {
    for (auto& kv : obj_)
        if (kv.first == key) return true;
    return false;
}

Json& Json::push(Json v) {
    if (type_ != Type::Arr) {
        type_ = Type::Arr;
        arr_.clear();
    }
    arr_.push_back(std::move(v));
    return *this;
}

size_t Json::size() const {
    if (type_ == Type::Arr) return arr_.size();
    if (type_ == Type::Obj) return obj_.size();
    return 0;
}

const Json& Json::at(size_t i) const {
    static Json null_value;
    if (type_ != Type::Arr || i >= arr_.size()) return null_value;
    return arr_[i];
}

const Json& Json::get(const std::string& key) const {
    static Json null_value;
    for (const auto& kv : obj_)
        if (kv.first == key) return kv.second;
    return null_value;
}

std::string Json::as_str(const std::string& fallback) const {
    return type_ == Type::Str ? s_ : fallback;
}

uint64_t Json::as_u(uint64_t fallback) const {
    switch (type_) {
        case Type::UInt: return u_;
        case Type::Int: return (uint64_t)i_;
        case Type::Str: {
            uint64_t v = 0;
            return parse_u64(s_, v) ? v : fallback;
        }
        default: return fallback;
    }
}

int64_t Json::as_i(int64_t fallback) const {
    switch (type_) {
        case Type::Int: return i_;
        case Type::UInt: return (int64_t)u_;
        default: return fallback;
    }
}

bool Json::as_bool(bool fallback) const {
    return type_ == Type::Bool ? b_ : fallback;
}

void Json::dump_string(std::string& out, const std::string& s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    out += '"';
}

void Json::dump_to(std::string& out, int indent, int depth) const {
    auto newline = [&](int d) {
        if (indent <= 0) return;
        out += '\n';
        out.append((size_t)indent * (size_t)d, ' ');
    };
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += b_ ? "true" : "false"; break;
        case Type::Int: out += std::to_string(i_); break;
        case Type::UInt: out += std::to_string(u_); break;
        case Type::Double: {
            if (!std::isfinite(d_)) {
                out += "null";
            } else {
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%.17g", d_);
                out += buf;
            }
            break;
        }
        case Type::Str: dump_string(out, s_); break;
        case Type::Arr: {
            out += '[';
            for (size_t k = 0; k < arr_.size(); ++k) {
                if (k) out += ',';
                newline(depth + 1);
                arr_[k].dump_to(out, indent, depth + 1);
            }
            if (!arr_.empty()) newline(depth);
            out += ']';
            break;
        }
        case Type::Obj: {
            out += '{';
            for (size_t k = 0; k < obj_.size(); ++k) {
                if (k) out += ',';
                newline(depth + 1);
                dump_string(out, obj_[k].first);
                out += indent > 0 ? ": " : ":";
                obj_[k].second.dump_to(out, indent, depth + 1);
            }
            if (!obj_.empty()) newline(depth);
            out += '}';
            break;
        }
    }
}

std::string Json::dump(int indent) const {
    std::string out;
    out.reserve(128);
    dump_to(out, indent, 0);
    return out;
}

}  // namespace aj
