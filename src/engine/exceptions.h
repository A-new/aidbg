#pragma once
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>

#include "util/json.h"

namespace aj {

// What to do when the debuggee raises an exception (design borrowed from
// Z0BDbgCli's scoped exignore/exstop model).
enum class ExAction { Break, Ignore, Pass };

struct ExceptionRule {
    uint32_t code = 0;
    ExAction action = ExAction::Break;
    uint64_t hits = 0;
};

class ExceptionPolicy {
public:
    ExAction lookup(uint32_t code) const;
    void set(uint32_t code, ExAction a);
    bool remove(uint32_t code);
    void clear();
    void reset_defaults();

    // When true, first-chance exceptions never stop the session (used while
    // single stepping through noisy code).
    bool ignore_all = false;

    // second-chance exceptions always stop, no matter the policy
    static bool is_breakpoint_code(uint32_t code);

    static std::string name_of(uint32_t code);
    static std::string action_text(ExAction a);
    static bool parse_action(const std::string& s, ExAction& out);

    Json to_json() const;
    std::string to_text() const;

    void note_hit(uint32_t code);

private:
    std::map<uint32_t, ExceptionRule> rules_;
};

}  // namespace aj
