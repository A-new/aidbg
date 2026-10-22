#pragma once
#include <windows.h>
#include <dbghelp.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// A DbgHelp type reference. Types are identified by (module base, type index).
struct TypeInfo {
    uint64_t mod_base = 0;
    uint32_t id = 0;      // DbgHelp type index
    uint32_t tag = 0;     // SymTag* enum value
    uint64_t length = 0;  // size in bytes
    bool valid = false;
};

struct FieldInfo {
    std::string name;
    uint64_t offset = 0;      // byte offset inside the parent
    uint64_t bit_position = 0;
    uint64_t bit_size = 0;
    bool is_bitfield = false;
    TypeInfo type;
    std::string type_name;
};

// Typed access to debuggee data, on top of DbgHelp's type information. This is
// what lets an agent read a struct field-by-field instead of guessing at raw
// bytes.
class Types {
public:
    void init(HANDLE proc) { proc_ = proc; }
    bool ready() const { return proc_ != nullptr; }

    // type lookups. mod_base scopes the lookup to one module; 0 means "search
    // every loaded module", which is slower and sometimes does not find UDTs.
    bool by_name(const std::string& name, TypeInfo& out, std::string& err,
                 uint64_t mod_base = 0);
    bool by_symbol(const std::string& symbol, TypeInfo& out, std::string& err);
    bool by_address(uint64_t addr, TypeInfo& out, std::string& err);

    // type relationships
    bool pointee(const TypeInfo& ptr, TypeInfo& out, std::string& err);
    bool array_element(const TypeInfo& arr, TypeInfo& out, uint64_t& count, std::string& err);
    bool field(const TypeInfo& parent, const std::string& name, FieldInfo& out, std::string& err);
    std::vector<FieldInfo> fields(const TypeInfo& parent);

    // classification
    bool is_pointer(const TypeInfo& t) const;
    bool is_aggregate(const TypeInfo& t) const;   // struct/union/class/array
    bool is_integral(const TypeInfo& t) const;
    bool is_float(const TypeInfo& t) const;
    bool is_udt(const TypeInfo& t) const;

    // pretty name: "int", "char*", "MyStruct", "int[10]"
    std::string name_of(const TypeInfo& t, int depth = 0);

    // struct/union/enum layout
    Json describe(const TypeInfo& t, int depth = 0);

private:
    bool get_u32(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, uint32_t& out) const;
    bool get_u64(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, uint64_t& out) const;
    bool get_str(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, std::string& out) const;
    bool child_of(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, TypeInfo& out) const;
    std::string base_type_name(uint32_t bt, uint64_t length) const;

    HANDLE proc_ = nullptr;
};

// Result of resolving a (possibly typed) expression such as `obj.next->value`.
struct TypedValue {
    uint64_t address = 0;   // where the value lives (0 for plain rvalues)
    uint64_t value = 0;     // the value, when it fits in 64 bits
    TypeInfo type;
    std::string type_name;
    std::string display;    // formatted value
};

// Resolves `base(.field|->field|[index])*` against the target. `eval_plain`
// resolves the base and index sub-expressions (register/symbol/arithmetic).
// Returns false with an error message when the chain does not type-check.
struct TypedResolver {
    std::function<bool(const std::string& text, uint64_t& out, std::string& err)> eval_plain;
    std::function<bool(uint64_t addr, void* buf, size_t n, std::string& err)> read;
    Types* types = nullptr;
};

bool resolve_typed(const std::string& expr, const TypedResolver& r, TypedValue& out,
                   std::string& err);

}  // namespace aj
