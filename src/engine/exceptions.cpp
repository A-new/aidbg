#include "engine/exceptions.h"

#include "util/strutil.h"

namespace aj {

namespace {
struct ExName {
    uint32_t code;
    const char* name;
};

const ExName kNames[] = {
    {0x80000003, "BREAKPOINT"},
    {0x80000004, "SINGLE_STEP"},
    {0x4000001E, "WX86_SINGLE_STEP"},
    {0x4000001F, "WX86_BREAKPOINT"},
    {0xC0000005, "ACCESS_VIOLATION"},
    {0xC000001D, "ILLEGAL_INSTRUCTION"},
    {0xC0000025, "NONCONTINUABLE_EXCEPTION"},
    {0xC0000026, "INVALID_DISPOSITION"},
    {0xC000008C, "ARRAY_BOUNDS_EXCEEDED"},
    {0xC000008D, "FLT_DENORMAL_OPERAND"},
    {0xC000008E, "FLT_DIVIDE_BY_ZERO"},
    {0xC000008F, "FLT_INEXACT_RESULT"},
    {0xC0000090, "FLT_INVALID_OPERATION"},
    {0xC0000091, "FLT_OVERFLOW"},
    {0xC0000092, "FLT_STACK_CHECK"},
    {0xC0000093, "FLT_UNDERFLOW"},
    {0xC0000094, "INT_DIVIDE_BY_ZERO"},
    {0xC0000095, "INT_OVERFLOW"},
    {0xC0000096, "PRIV_INSTRUCTION"},
    {0xC00000FD, "STACK_OVERFLOW"},
    {0xC0000135, "DLL_NOT_FOUND"},
    {0xC0000138, "ORDINAL_NOT_FOUND"},
    {0xC0000139, "ENTRYPOINT_NOT_FOUND"},
    {0xC0000142, "DLL_INIT_FAILED"},
    {0xC0000374, "HEAP_CORRUPTION"},
    {0xC0000409, "STACK_BUFFER_OVERRUN"},
    {0xC0000417, "INVALID_CRUNTIME_PARAMETER"},
    {0xC0000420, "ASSERTION_FAILURE"},
    {0xE06D7363, "CPP_EXCEPTION (MSVC)"},
    {0xE0434352, "CLR_EXCEPTION"},
    {0x406D1388, "THREAD_NAME"},
    {0x40010006, "DBG_PRINTEXCEPTION_C"},
    {0x4001000A, "DBG_PRINTEXCEPTION_WIDE_C"},
};
}

void ExceptionPolicy::reset_defaults() {
    rules_.clear();
    // First chance: stop so the AI/operator sees it. User can relax per code.
    for (const auto& n : kNames) {
        ExceptionRule r;
        r.code = n.code;
        r.action = (n.code == 0x406D1388 || n.code == 0x40010006 || n.code == 0x4001000A)
                       ? ExAction::Pass
                       : ExAction::Break;
        rules_[n.code] = r;
    }
    ignore_all = false;
}

ExAction ExceptionPolicy::lookup(uint32_t code) const {
    if (ignore_all) return ExAction::Ignore;
    auto it = rules_.find(code);
    if (it != rules_.end()) return it->second.action;
    return ExAction::Break;  // unknown exceptions are reported
}

void ExceptionPolicy::set(uint32_t code, ExAction a) {
    rules_[code] = ExceptionRule{code, a, 0};
}

bool ExceptionPolicy::remove(uint32_t code) { return rules_.erase(code) > 0; }

void ExceptionPolicy::clear() {
    rules_.clear();
    ignore_all = false;
}

void ExceptionPolicy::note_hit(uint32_t code) {
    auto it = rules_.find(code);
    if (it != rules_.end())
        it->second.hits++;
    else {
        ExceptionRule r;
        r.code = code;
        r.action = ExAction::Break;
        r.hits = 1;
        rules_[code] = r;
    }
}

bool ExceptionPolicy::is_breakpoint_code(uint32_t code) {
    return code == 0x80000003 || code == 0x80000004 || code == 0x4000001E || code == 0x4000001F;
}

std::string ExceptionPolicy::name_of(uint32_t code) {
    for (const auto& n : kNames)
        if (n.code == code) return n.name;
    return fmt("EXCEPTION_0x%08X", code);
}

std::string ExceptionPolicy::action_text(ExAction a) {
    switch (a) {
        case ExAction::Break: return "break";
        case ExAction::Ignore: return "ignore";
        case ExAction::Pass: return "pass";
    }
    return "?";
}

bool ExceptionPolicy::parse_action(const std::string& s, ExAction& out) {
    std::string t = to_lower(trim(s));
    if (t == "break" || t == "b") {
        out = ExAction::Break;
        return true;
    }
    if (t == "ignore" || t == "i") {
        out = ExAction::Ignore;
        return true;
    }
    if (t == "pass" || t == "p") {
        out = ExAction::Pass;
        return true;
    }
    return false;
}

Json ExceptionPolicy::to_json() const {
    Json arr = Json::arr();
    for (const auto& kv : rules_) {
        Json j = Json::obj();
        j.set_str("code", fmt("0x%08X", kv.first));
        j.set_u("code_value", kv.first);
        j.set_str("name", name_of(kv.first));
        j.set_str("action", action_text(kv.second.action));
        j.set_u("hits", kv.second.hits);
        arr.push(std::move(j));
    }
    Json out = Json::obj();
    out.set_bool("ignore_all", ignore_all);
    out.set("rules", arr);
    return out;
}

std::string ExceptionPolicy::to_text() const {
    std::string out = fmt("ignore_all = %s\n", ignore_all ? "on" : "off");
    out += fmt("%-12s %-28s %-8s %s\n", "code", "name", "action", "hits");
    out += std::string(62, '-') + "\n";
    for (const auto& kv : rules_) {
        out += fmt("0x%08X   %-28s %-8s %llu\n", kv.first, name_of(kv.first).c_str(),
                   action_text(kv.second.action).c_str(), (unsigned long long)kv.second.hits);
    }
    return out;
}

}  // namespace aj
