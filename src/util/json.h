#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aj {

// Minimal JSON value tree. Purpose-built for machine readable debugger output.
// 64-bit addresses are serialized as hex *strings* ("0x7ff6aabb0000") so that no
// precision is lost in JSON consumers (JS numbers only hold 2^53).
class Json {
public:
    enum class Type { Null, Bool, Int, UInt, Double, Str, Arr, Obj };

    Json() = default;

    static Json null() { return Json(); }
    static Json boolean(bool v);
    static Json i(int64_t v);
    static Json u(uint64_t v);
    static Json d(double v);
    static Json s(std::string v);
    static Json hex(uint64_t v);  // -> "0x..." string
    static Json arr();
    static Json obj();

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }

    // object
    Json& set(const std::string& key, Json v);
    Json& set_str(const std::string& key, const std::string& v);
    Json& set_hex(const std::string& key, uint64_t v);
    Json& set_u(const std::string& key, uint64_t v);
    Json& set_i(const std::string& key, int64_t v);
    Json& set_d(const std::string& key, double v);
    Json& set_bool(const std::string& key, bool v);
    bool has(const std::string& key) const;

    // array
    Json& push(Json v);

    // read accessors (used when rendering text from structured data)
    size_t size() const;
    const Json& at(size_t i) const;
    const Json& get(const std::string& key) const;
    std::string as_str(const std::string& fallback = {}) const;
    uint64_t as_u(uint64_t fallback = 0) const;
    bool as_bool(bool fallback = false) const;

    // indent == 0 -> compact single line (best for JSONL / AI parsing)
    std::string dump(int indent = 0) const;

private:
    void dump_to(std::string& out, int indent, int depth) const;
    static void dump_string(std::string& out, const std::string& s);

    Type type_ = Type::Null;
    bool b_ = false;
    int64_t i_ = 0;
    uint64_t u_ = 0;
    double d_ = 0;
    std::string s_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;
};

}  // namespace aj
