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

bool Symbols::init(uint32_t pid, HANDLE proc, const std::string& search_path, std::string& err) {
    if (!proc) return false;
    SymSetOptions(kSymOptions);
    // an old session for a recycled pid must not leak module state into the
    // new process
    auto it = procs_.find(pid);
    if (it != procs_.end() && it->second != proc) {
        SymCleanup(it->second);
        procs_.erase(it);
    }
    // Wide entry point: module/PDB paths are not ASCII in practice (anything
    // containing a non-ASCII directory name failed to load with the ANSI API).
    std::wstring wsearch = to_wide(search_path);
    if (!SymInitializeW(proc, wsearch.empty() ? nullptr : wsearch.c_str(), FALSE)) {
        err = fmt("SymInitialize failed: %s", last_error_text().c_str());
        return false;
    }
    procs_[pid] = proc;
    return true;
}

void Symbols::shutdown() {
    for (auto& kv : procs_) SymCleanup(kv.second);
    procs_.clear();
    current_ = 0;
}

bool Symbols::ready() const {
    return cur() != nullptr;
}

HANDLE Symbols::cur() const {
    auto it = procs_.find(current_);
    return it == procs_.end() ? nullptr : it->second;
}

bool Symbols::load_module(uint32_t pid, uint64_t base, size_t size, const std::string& path,
                          const std::string& name, std::string& err) {
    auto it = procs_.find(pid);
    if (it == procs_.end()) return true;  // symbol support is optional
    HANDLE proc = it->second;
    std::wstring wpath = to_wide(path);
    std::wstring wname = to_wide(name);
    DWORD64 r = SymLoadModuleExW(proc, nullptr, wpath.empty() ? nullptr : wpath.c_str(),
                                 wname.empty() ? nullptr : wname.c_str(), (DWORD64)base,
                                 (DWORD)size, nullptr, 0);
    if (!r) {
        err = fmt("SymLoadModuleEx(%s) failed: %s", name.c_str(), last_error_text().c_str());
        return false;
    }
    return true;
}

bool Symbols::unload_module(uint32_t pid, uint64_t base) {
    auto it = procs_.find(pid);
    if (it == procs_.end()) return true;
    SymUnloadModule64(it->second, (DWORD64)base);
    return true;
}

bool Symbols::resolve_name(const std::string& name, uint64_t& out, std::string& err) {
    HANDLE proc = cur();
    if (!proc) {
        err = "symbol support is not available (no session for the current process)";
        return false;
    }
    // SymFromName handles "module!symbol" and plain "symbol".
    // "module+0xoff" is resolved by the Engine through its own module table.
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(proc, name.c_str(), si)) {
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
    HANDLE proc = cur();
    if (!proc) return false;
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    DWORD64 d = 0;
    if (!SymFromAddr(proc, (DWORD64)addr, &d, si)) return false;
    name = sym_name(si);
    disp = (uint64_t)d;
    return true;
}

bool Symbols::function_extent(uint64_t addr, uint64_t& start, uint64_t& end,
                              std::string& name) {
    start = end = 0;
    name.clear();
    HANDLE proc = cur();
    if (!proc) return false;
    std::vector<char> buf(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    SYMBOL_INFO* si = (SYMBOL_INFO*)buf.data();
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MAX_SYM_NAME;
    DWORD64 d = 0;
    if (!SymFromAddr(proc, (DWORD64)addr, &d, si)) return false;
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
    HANDLE proc = cur();
    if (!proc) return false;
    IMAGEHLP_LINEW64 ln;
    std::memset(&ln, 0, sizeof(ln));
    ln.SizeOfStruct = sizeof(ln);
    DWORD d = 0;
    if (!SymGetLineFromAddrW64(proc, (DWORD64)addr, &d, &ln)) return false;
    file = ln.FileName ? to_utf8(ln.FileName) : "";
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
    HANDLE proc = cur();
    if (!proc) return arr;
    EnumCtx ctx{&arr, max, 0};
    std::string mask_str = mask.empty() ? "*" : mask;
    SymEnumSymbols(proc, (DWORD64)0, mask_str.c_str(), enum_cb, &ctx);
    return arr;
}

}  // namespace aj
