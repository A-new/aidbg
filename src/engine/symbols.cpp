#include "engine/symbols.h"

#include <dbghelp.h>

#include <cstring>
#include <vector>

#include "engine/win_compat.h"
#include "util/strutil.h"

namespace aj {

namespace {
constexpr DWORD kSymOptions = SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                              SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_AUTO_PUBLICS |
                              SYMOPT_INCLUDE_32BIT_MODULES;

std::string sym_name(const SYMBOL_INFO* si) {
    if (!si) return {};
    return std::string(si->Name, si->NameLen);
}
}  // namespace

bool Symbols::init(HANDLE proc, const std::string& search_path, std::string& err) {
    SymSetOptions(kSymOptions);
    // DbgHelp's narrow entry points expect the ANSI codepage; symbol names and
    // PDB paths are ASCII in practice.
    if (!SymInitialize(proc, search_path.empty() ? nullptr : search_path.c_str(), FALSE)) {
        err = fmt("SymInitialize failed: %s", last_error_text().c_str());
        return false;
    }
    proc_ = proc;
    ready_ = true;
    return true;
}

void Symbols::shutdown() {
    if (ready_ && proc_) {
        SymCleanup(proc_);
        ready_ = false;
    }
}

bool Symbols::load_module(uint64_t base, size_t size, const std::string& path,
                          const std::string& name, std::string& err) {
    if (!ready_) return true;  // symbol support is optional
    DWORD64 r = SymLoadModuleEx(proc_, nullptr, path.c_str(),
                                name.empty() ? nullptr : name.c_str(), (DWORD64)base,
                                (DWORD)size, nullptr, 0);
    if (!r) {
        err = fmt("SymLoadModuleEx(%s) failed: %s", name.c_str(), last_error_text().c_str());
        return false;
    }
    return true;
}

bool Symbols::unload_module(uint64_t base) {
    if (!ready_) return true;
    SymUnloadModule64(proc_, (DWORD64)base);
    return true;
}

bool Symbols::resolve_name(const std::string& name, uint64_t& out, std::string& err) {
    if (!ready_) {
        err = "symbol support is not available (DbgHelp init failed)";
        return false;
    }
    // SymFromName handles "module!symbol" and plain "symbol".
    // "module+0xoff" is resolved by the Engine through its own module table.
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(proc_, name.c_str(), si)) {
        err = fmt("symbol not found: %s", name.c_str());
        return false;
    }
    out = (uint64_t)si->Address;
    return true;
}

bool Symbols::lookup_address(uint64_t addr, std::string& name, uint64_t& disp,
                             std::string& err) {
    name.clear();
    disp = 0;
    if (!ready_) return false;
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    DWORD64 d = 0;
    if (!SymFromAddr(proc_, (DWORD64)addr, &d, si)) return false;
    name = sym_name(si);
    disp = (uint64_t)d;
    return true;
}

bool Symbols::function_extent(uint64_t addr, uint64_t& start, uint64_t& end,
                              std::string& name) {
    start = end = 0;
    name.clear();
    if (!ready_) return false;
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    DWORD64 d = 0;
    if (!SymFromAddr(proc_, (DWORD64)addr, &d, si)) return false;
    // Only functions carry a usable extent; a data symbol's size is not a code
    // range and would produce a nonsense graph. SymTagEnum values from
    // dbghelp.h: SymTagFunction = 5, SymTagPublicSymbol = 10.
    if (si->Tag != 5 && si->Tag != 10) return false;
    if (!si->Address || si->Size == 0) return false;
    name = sym_name(si);
    start = (uint64_t)si->Address;
    end = start + (uint64_t)si->Size;
    return true;
}

bool Symbols::line_from_address(uint64_t addr, std::string& file, uint32_t& line,
                                uint64_t& disp) {
    file.clear();
    line = 0;
    disp = 0;
    if (!ready_) return false;
    IMAGEHLP_LINE64 ln;
    std::memset(&ln, 0, sizeof(ln));
    ln.SizeOfStruct = sizeof(ln);
    DWORD d = 0;
    if (!SymGetLineFromAddr64(proc_, (DWORD64)addr, &d, &ln)) return false;
    file = ln.FileName ? ln.FileName : "";
    line = ln.LineNumber;
    disp = d;
    return true;
}

namespace {
struct EnumCtx {
    Json* arr;
    size_t max;
    size_t count;
};

BOOL CALLBACK enum_cb(SYMBOL_INFO* si, ULONG /*size*/, PVOID user) {
    EnumCtx* c = (EnumCtx*)user;
    if (c->count >= c->max) return FALSE;
    Json j = Json::obj();
    j.set_str("name", sym_name(si));
    j.set_hex("address", (uint64_t)si->Address);
    j.set_u("size", (uint64_t)si->Size);
    if (si->Tag) j.set_u("tag", si->Tag);
    c->arr->push(std::move(j));
    c->count++;
    return TRUE;
}
}  // namespace

Json Symbols::enumerate(const std::string& mask, size_t max) {
    Json arr = Json::arr();
    if (!ready_) return arr;
    EnumCtx ctx{&arr, max, 0};
    std::string mask_str = mask.empty() ? "*" : mask;
    SymEnumSymbols(proc_, (DWORD64)0, mask_str.c_str(), enum_cb, &ctx);
    return arr;
}

}  // namespace aj
