#include "engine/types.h"

#include <dbghelp.h>

#include <cstring>

#include "util/strutil.h"

namespace aj {

namespace {

// SymTagEnum values (dbghelp.h), kept as constants so this file does not depend
// on enum ordering surprises across SDK versions.
enum : uint32_t {
    TAG_NULL = 0,
    TAG_EXE = 1,
    TAG_FUNCTION = 5,
    TAG_DATA = 7,
    TAG_PUBLIC_SYMBOL = 10,
    TAG_UDT = 11,
    TAG_ENUM = 12,
    TAG_FUNCTIONTYPE = 13,
    TAG_POINTER = 14,
    TAG_ARRAY = 15,
    TAG_BASETYPE = 16,
    TAG_TYPEDEF = 17,
    TAG_BASECLASS = 18,
};

// BasicType values (cvconst.h)
enum : uint32_t {
    BT_NONE = 0, BT_VOID = 1, BT_CHAR = 2, BT_WCHAR = 3, BT_INT = 6, BT_UINT = 7,
    BT_FLOAT = 8, BT_BCD = 9, BT_BOOL = 10, BT_LONG = 13, BT_ULONG = 14,
    BT_CURRENCY = 25, BT_DATE = 26, BT_VARIANT = 27, BT_COMPLEX = 28, BT_BIT = 29,
    BT_BSTR = 30, BT_HRESULT = 31,
};

// UdtKind values
enum : uint32_t { UDT_STRUCT = 0, UDT_CLASS = 1, UDT_UNION = 2 };

const char* udt_kind_text(uint32_t k) {
    switch (k) {
        case UDT_STRUCT: return "struct";
        case UDT_CLASS: return "class";
        case UDT_UNION: return "union";
    }
    return "struct";
}

}  // namespace

bool Types::get_u32(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, uint32_t& out) const {
    if (!proc_ || !t.id) return false;
    out = 0;
    return SymGetTypeInfo(proc_, (DWORD64)t.mod_base, (ULONG)t.id, what, &out) != FALSE;
}

bool Types::get_u64(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, uint64_t& out) const {
    if (!proc_ || !t.id) return false;
    out = 0;
    return SymGetTypeInfo(proc_, (DWORD64)t.mod_base, (ULONG)t.id, what, &out) != FALSE;
}

bool Types::get_str(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, std::string& out) const {
    out.clear();
    if (!proc_ || !t.id) return false;
    PWSTR buf = nullptr;
    if (!SymGetTypeInfo(proc_, (DWORD64)t.mod_base, (ULONG)t.id, what, &buf) || !buf)
        return false;
    out = to_utf8(buf);
    LocalFree(buf);
    return true;
}

bool Types::child_of(const TypeInfo& t, IMAGEHLP_SYMBOL_TYPE_INFO what, TypeInfo& out) const {
    uint32_t id = 0;
    if (!get_u32(t, what, id) || !id) return false;
    out = TypeInfo();
    out.mod_base = t.mod_base;
    out.id = id;
    uint32_t tag = 0;
    if (get_u32(out, TI_GET_SYMTAG, tag)) out.tag = tag;
    uint64_t len = 0;
    if (get_u64(out, TI_GET_LENGTH, len)) out.length = len;
    out.valid = true;
    return true;
}

std::string Types::base_type_name(uint32_t bt, uint64_t length) const {
    switch (bt) {
        case BT_VOID: return "void";
        case BT_CHAR: return "char";
        case BT_WCHAR: return "wchar_t";
        case BT_INT:
        case BT_LONG:
            switch (length) {
                case 1: return "int8";
                case 2: return "int16";
                case 4: return bt == BT_LONG ? "long" : "int";
                case 8: return "int64";
            }
            return "int";
        case BT_UINT:
        case BT_ULONG:
            switch (length) {
                case 1: return "uint8";
                case 2: return "uint16";
                case 4: return bt == BT_ULONG ? "unsigned long" : "unsigned int";
                case 8: return "uint64";
            }
            return "unsigned int";
        case BT_FLOAT:
            return length == 4 ? "float" : (length == 8 ? "double" : "float");
        case BT_BOOL: return "bool";
        case BT_HRESULT: return "HRESULT";
        default: return fmt("base<%u>", bt);
    }
}

bool Types::is_pointer(const TypeInfo& t) const { return t.valid && t.tag == TAG_POINTER; }
bool Types::is_udt(const TypeInfo& t) const { return t.valid && t.tag == TAG_UDT; }

bool Types::is_aggregate(const TypeInfo& t) const {
    return t.valid && (t.tag == TAG_UDT || t.tag == TAG_ARRAY);
}

bool Types::is_integral(const TypeInfo& t) const {
    if (!t.valid) return false;
    if (t.tag == TAG_ENUM) return true;
    if (t.tag != TAG_BASETYPE) return false;
    uint32_t bt = 0;
    if (!get_u32(t, TI_GET_BASETYPE, bt)) return false;
    return bt == BT_CHAR || bt == BT_WCHAR || bt == BT_INT || bt == BT_UINT ||
           bt == BT_LONG || bt == BT_ULONG || bt == BT_BOOL || bt == BT_BIT ||
           bt == BT_HRESULT;
}

bool Types::is_float(const TypeInfo& t) const {
    if (!t.valid || t.tag != TAG_BASETYPE) return false;
    uint32_t bt = 0;
    return get_u32(t, TI_GET_BASETYPE, bt) && bt == BT_FLOAT;
}

bool Types::by_name(const std::string& name, TypeInfo& out, std::string& err,
                    uint64_t mod_base) {
    out = TypeInfo();
    if (!proc_) {
        err = "type information is not available";
        return false;
    }
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    if (!SymGetTypeFromName(proc_, (DWORD64)mod_base, name.c_str(), si)) {
        err = fmt("unknown type: %s", name.c_str());
        return false;
    }
    out.mod_base = (uint64_t)si->ModBase;
    out.id = si->TypeIndex;
    out.valid = true;
    uint32_t tag = 0;
    if (get_u32(out, TI_GET_SYMTAG, tag)) out.tag = tag;
    uint64_t len = 0;
    if (get_u64(out, TI_GET_LENGTH, len)) out.length = len;
    return true;
}

bool Types::by_symbol(const std::string& symbol, TypeInfo& out, std::string& err) {
    out = TypeInfo();
    if (!proc_) {
        err = "type information is not available";
        return false;
    }
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(proc_, symbol.c_str(), si)) {
        err = fmt("unknown symbol: %s", symbol.c_str());
        return false;
    }
    if (!si->TypeIndex) {
        err = fmt("no type information for: %s", symbol.c_str());
        return false;
    }
    out.mod_base = (uint64_t)si->ModBase;
    out.id = si->TypeIndex;
    out.valid = true;
    uint32_t tag = 0;
    if (get_u32(out, TI_GET_SYMTAG, tag)) out.tag = tag;
    uint64_t len = 0;
    if (get_u64(out, TI_GET_LENGTH, len)) out.length = len;
    return true;
}

bool Types::by_address(uint64_t addr, TypeInfo& out, std::string& err) {
    out = TypeInfo();
    if (!proc_) {
        err = "type information is not available";
        return false;
    }
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    DWORD64 disp = 0;
    if (!SymFromAddr(proc_, (DWORD64)addr, &disp, si)) {
        err = fmt("no symbol at %s", hex8(addr).c_str());
        return false;
    }
    if (!si->TypeIndex) {
        err = fmt("no type information at %s", hex8(addr).c_str());
        return false;
    }
    out.mod_base = (uint64_t)si->ModBase;
    out.id = si->TypeIndex;
    out.valid = true;
    uint32_t tag = 0;
    if (get_u32(out, TI_GET_SYMTAG, tag)) out.tag = tag;
    uint64_t len = 0;
    if (get_u64(out, TI_GET_LENGTH, len)) out.length = len;
    return true;
}

bool Types::pointee(const TypeInfo& ptr, TypeInfo& out, std::string& err) {
    if (!is_pointer(ptr)) {
        err = "not a pointer type";
        return false;
    }
    if (!child_of(ptr, TI_GET_TYPEID, out)) {
        err = "cannot resolve pointee type";
        return false;
    }
    return true;
}

bool Types::array_element(const TypeInfo& arr, TypeInfo& out, uint64_t& count,
                          std::string& err) {
    if (!arr.valid || arr.tag != TAG_ARRAY) {
        err = "not an array type";
        return false;
    }
    count = 0;
    get_u64(arr, TI_GET_COUNT, count);
    if (!child_of(arr, TI_GET_TYPEID, out)) {
        err = "cannot resolve array element type";
        return false;
    }
    return true;
}

bool Types::field(const TypeInfo& parent, const std::string& name, FieldInfo& out,
                  std::string& err) {
    auto all = fields(parent);
    for (auto& f : all) {
        if (to_lower(f.name) == to_lower(name)) {
            out = f;
            return true;
        }
    }
    err = fmt("type %s has no field '%s'", name_of(parent).c_str(), name.c_str());
    return false;
}

std::vector<FieldInfo> Types::fields(const TypeInfo& parent) {
    std::vector<FieldInfo> out;
    if (!parent.valid) return out;

    // Data members only; skip base classes and nested types.
    uint32_t count = 0;
    if (!get_u32(parent, TI_GET_CHILDRENCOUNT, count) || count == 0) return out;
    if (count > 4096) count = 4096;

    size_t bytes = sizeof(TI_FINDCHILDREN_PARAMS) + (size_t)count * sizeof(ULONG);
    std::vector<char> storage(bytes);
    TI_FINDCHILDREN_PARAMS* fc = (TI_FINDCHILDREN_PARAMS*)storage.data();
    fc->Count = count;
    fc->Start = 0;
    if (!SymGetTypeInfo(proc_, (DWORD64)parent.mod_base, (ULONG)parent.id, TI_FINDCHILDREN, fc))
        return out;

    for (uint32_t i = 0; i < count; ++i) {
        TypeInfo ct;
        ct.mod_base = parent.mod_base;
        ct.id = fc->ChildId[i];
        ct.valid = true;
        uint32_t tag = 0;
        if (get_u32(ct, TI_GET_SYMTAG, tag)) ct.tag = tag;
        if (ct.tag != TAG_DATA && ct.tag != TAG_BASECLASS) continue;

        FieldInfo f;
        get_str(ct, TI_GET_SYMNAME, f.name);
        uint64_t off = 0;
        if (get_u64(ct, TI_GET_OFFSET, off)) f.offset = off;

        // The member entry is a SymTagData node; its declared type is one hop
        // away via TI_GET_TYPEID.
        TypeInfo ft;
        if (child_of(ct, TI_GET_TYPEID, ft)) {
            f.type = ft;
            f.type_name = name_of(ft);
        } else {
            f.type = ct;
            f.type_name = name_of(ct);
        }

        // bitfields report a bit position on the data member
        uint32_t bitpos = 0;
        if (get_u32(ct, TI_GET_BITPOSITION, bitpos)) {
            f.bit_position = bitpos;
            f.is_bitfield = true;
        }
        out.push_back(std::move(f));
    }
    return out;
}

std::string Types::name_of(const TypeInfo& t, int depth) {
    if (!t.valid) return "<unknown>";
    if (depth > 6) return "...";

    switch (t.tag) {
        case TAG_BASETYPE: {
            uint32_t bt = 0;
            get_u32(t, TI_GET_BASETYPE, bt);
            return base_type_name(bt, t.length);
        }
        case TAG_POINTER: {
            TypeInfo point;
            if (child_of(t, TI_GET_TYPEID, point)) {
                std::string inner = name_of(point, depth + 1);
                if (point.tag == TAG_FUNCTIONTYPE) return inner;
                return inner + "*";
            }
            return "void*";
        }
        case TAG_ARRAY: {
            TypeInfo elem;
            uint64_t count = 0;
            if (child_of(t, TI_GET_TYPEID, elem)) {
                get_u64(t, TI_GET_COUNT, count);
                return fmt("%s[%llu]", name_of(elem, depth + 1).c_str(),
                           (unsigned long long)count);
            }
            return "array";
        }
        case TAG_UDT: {
            std::string n;
            if (get_str(t, TI_GET_SYMNAME, n) && !n.empty()) return n;
            return "struct";
        }
        case TAG_ENUM: {
            std::string n;
            if (get_str(t, TI_GET_SYMNAME, n) && !n.empty()) return n;
            return "enum";
        }
        case TAG_TYPEDEF: {
            std::string n;
            if (get_str(t, TI_GET_SYMNAME, n) && !n.empty()) return n;
            TypeInfo inner;
            if (child_of(t, TI_GET_TYPEID, inner)) return name_of(inner, depth + 1);
            return "typedef";
        }
        case TAG_FUNCTIONTYPE: return "function";
        default: {
            std::string n;
            if (get_str(t, TI_GET_SYMNAME, n) && !n.empty()) return n;
            return fmt("type<%u>", t.tag);
        }
    }
}

Json Types::describe(const TypeInfo& t, int depth) {
    Json j = Json::obj();
    if (!t.valid) return j;
    j.set_str("type", name_of(t));
    j.set_u("size", t.length);
    j.set_str("tag", t.tag == TAG_UDT ? "udt" : (t.tag == TAG_ENUM ? "enum" : "other"));

    if (t.tag == TAG_UDT) {
        uint32_t kind = 0;
        get_u32(t, TI_GET_UDTKIND, kind);
        j.set_str("kind", udt_kind_text(kind));
    }

    if (t.tag == TAG_UDT && depth < 3) {
        Json arr = Json::arr();
        for (auto& f : fields(t)) {
            Json fj = Json::obj();
            fj.set_str("name", f.name);
            fj.set_hex("offset", f.offset);
            fj.set_str("type", f.type_name);
            fj.set_u("size", f.type.length);
            if (f.is_bitfield) fj.set_u("bit_position", f.bit_position);
            arr.push(std::move(fj));
        }
        j.set("fields", arr);
    }
    return j;
}

// ------------------------------------------------------- typed expression walk

namespace {

// Splits `base(.field|->field|[index])*` into a base and a chain of operations,
// without touching the insides of brackets.
struct AccessOp {
    enum Kind { Field, DerefField, Index } kind;
    std::string text;   // field name, or index expression
};

bool split_chain(const std::string& expr, std::string& base, std::vector<AccessOp>& ops,
                 std::string& err) {
    int depth = 0;
    size_t i = 0;
    size_t base_end = std::string::npos;
    for (; i < expr.size(); ++i) {
        char c = expr[i];
        if (c == '[') {
            if (depth == 0 && base_end == std::string::npos) base_end = i;
            ++depth;
        } else if (c == ']') {
            --depth;
            if (depth < 0) {
                err = "unbalanced ']'";
                return false;
            }
        } else if (depth == 0 && c == '.') {
            if (base_end == std::string::npos) base_end = i;
            break;
        }
    }
    if (base_end == std::string::npos) {
        base = trim(expr);
        return !base.empty();
    }
    base = trim(expr.substr(0, base_end));

    // walk the remaining operators
    size_t p = base_end;
    while (p < expr.size()) {
        if (expr[p] == '.') {
            size_t s = p + 1;
            size_t e = s;
            while (e < expr.size() && (std::isalnum((unsigned char)expr[e]) || expr[e] == '_'))
                ++e;
            if (e == s) {
                err = "expected a field name after '.'";
                return false;
            }
            ops.push_back({AccessOp::Field, expr.substr(s, e - s)});
            p = e;
        } else if (expr[p] == '-' && p + 1 < expr.size() && expr[p + 1] == '>') {
            size_t s = p + 2;
            size_t e = s;
            while (e < expr.size() && (std::isalnum((unsigned char)expr[e]) || expr[e] == '_'))
                ++e;
            if (e == s) {
                err = "expected a field name after '->'";
                return false;
            }
            ops.push_back({AccessOp::DerefField, expr.substr(s, e - s)});
            p = e;
        } else if (expr[p] == '[') {
            int d = 0;
            size_t s = p + 1;
            size_t e = s;
            for (; e < expr.size(); ++e) {
                if (expr[e] == '[') ++d;
                else if (expr[e] == ']') {
                    if (d == 0) break;
                    --d;
                }
            }
            if (e >= expr.size()) {
                err = "unbalanced '['";
                return false;
            }
            ops.push_back({AccessOp::Index, trim(expr.substr(s, e - s))});
            p = e + 1;
        } else if (std::isspace((unsigned char)expr[p])) {
            ++p;
        } else {
            err = fmt("unexpected '%c' in expression", expr[p]);
            return false;
        }
    }
    return true;
}

bool read_value(const TypedResolver& r, uint64_t addr, const TypeInfo& t, uint64_t& out) {
    out = 0;
    size_t n = (size_t)(t.length ? t.length : 8);
    uint8_t buf[8] = {0};
    if (n > 8) n = 8;
    std::string e;
    if (!r.read(addr, buf, n, e)) return false;
    switch (n) {
        case 1: out = buf[0]; break;
        case 2: out = *(uint16_t*)buf; break;
        case 4: out = *(uint32_t*)buf; break;
        default: out = *(uint64_t*)buf; break;
    }
    return true;
}

}  // namespace

bool resolve_typed(const std::string& expr, const TypedResolver& r, TypedValue& out,
                   std::string& err) {
    if (!r.types) {
        err = "type information is not available";
        return false;
    }
    Types& T = *r.types;

    std::string base;
    std::vector<AccessOp> ops;
    if (!split_chain(expr, base, ops, err)) return false;

    // resolve the base to an address plus a type
    uint64_t addr = 0;
    if (!r.eval_plain(base, addr, err)) return false;

    TypeInfo type;
    std::string terr;
    if (!T.by_symbol(base, type, terr)) {
        // not a typed symbol: maybe it is an expression yielding an address
        if (!T.by_address(addr, type, terr)) {
            out.address = addr;
            out.value = addr;
            out.display = hex8(addr);
            if (ops.empty()) return true;
            err = "cannot determine the type of '" + base + "' (" + terr + ")";
            return false;
        }
    }

    // walk the access chain
    for (const auto& op : ops) {
        if (op.kind == AccessOp::Index) {
            uint64_t idx = 0;
            if (!r.eval_plain(op.text, idx, err)) return false;
            if (T.is_pointer(type)) {
                TypeInfo point;
                if (!T.pointee(type, point, err)) return false;
                uint64_t ptr = 0;
                if (!read_value(r, addr, type, ptr)) {
                    err = "cannot read pointer at " + hex8(addr);
                    return false;
                }
                addr = ptr + idx * (point.length ? point.length : 1);
                type = point;
            } else if (type.valid && type.tag == TAG_ARRAY) {
                TypeInfo elem;
                uint64_t count = 0;
                if (!T.array_element(type, elem, count, err)) return false;
                if (count && idx >= count) {
                    err = fmt("index %llu out of bounds (size %llu)",
                              (unsigned long long)idx, (unsigned long long)count);
                    return false;
                }
                addr += idx * (elem.length ? elem.length : 1);
                type = elem;
            } else {
                err = "'" + base + "' is neither a pointer nor an array";
                return false;
            }
            continue;
        }

        bool deref = (op.kind == AccessOp::DerefField);
        if (deref) {
            TypeInfo point;
            if (!T.pointee(type, point, err)) return false;
            uint64_t ptr = 0;
            if (!read_value(r, addr, type, ptr)) {
                err = "cannot read pointer at " + hex8(addr);
                return false;
            }
            addr = ptr;
            type = point;
        }
        if (!T.is_udt(type)) {
            err = "'" + op.text + "' is not a struct/union member access target (type is " +
                  T.name_of(type) + ")";
            return false;
        }
        FieldInfo f;
        if (!T.field(type, op.text, f, err)) return false;
        addr += f.offset;
        type = f.type;
    }

    out.address = addr;
    out.type = type;
    out.type_name = T.name_of(type);

    // render the value
    if (T.is_integral(type)) {
        uint64_t v = 0;
        if (read_value(r, addr, type, v)) {
            out.value = v;
            if (type.length == 1) {
                out.display = fmt("%llu ('%c')", (unsigned long long)v,
                                  (v >= 0x20 && v < 0x7f) ? (char)v : '.');
            } else {
                out.display = fmt("%llu (%s)", (unsigned long long)v, hex8(v).c_str());
            }
        } else {
            out.display = "<unreadable>";
        }
    } else if (T.is_float(type)) {
        std::string e;
        if (type.length == 4) {
            uint32_t raw = 0;
            if (r.read(addr, &raw, 4, e)) {
                float f;
                std::memcpy(&f, &raw, 4);
                out.value = raw;
                out.display = fmt("%g", (double)f);
            } else {
                out.display = "<unreadable>";
            }
        } else {
            uint64_t raw = 0;
            if (r.read(addr, &raw, 8, e)) {
                double d;
                std::memcpy(&d, &raw, 8);
                out.value = raw;
                out.display = fmt("%g", d);
            } else {
                out.display = "<unreadable>";
            }
        }
    } else if (T.is_pointer(type)) {
        uint64_t v = 0;
        if (read_value(r, addr, type, v)) {
            out.value = v;
            out.display = hex8(v);
        } else {
            out.display = "<unreadable>";
        }
    } else if (type.valid && type.tag == TAG_ARRAY && type.length > 0 && type.length <= 256) {
        std::vector<uint8_t> buf((size_t)type.length);
        if (r.read(addr, buf.data(), buf.size(), err)) {
            bool printable = true;
            for (uint8_t c : buf)
                if (c != 0 && (c < 0x20 || c > 0x7e)) printable = false;
            if (printable) {
                std::string s;
                for (uint8_t c : buf)
                    if (c) s += (char)c;
                out.display = "\"" + s + "\"";
            } else {
                out.display = bytes_to_hex(buf);
            }
        } else {
            out.display = "<unreadable>";
        }
    } else {
        // aggregates: the caller renders the field list
        out.display = out.type_name;
    }
    return true;
}

}  // namespace aj
