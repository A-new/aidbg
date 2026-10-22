#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "util/json.h"

namespace aj {

// User labels and comments, anchored to module+RVA (borrowed from Syser's
// CSymbolModule / CCommentModule). Anchoring to the module instead of the
// absolute address keeps them valid across ASLR slides and target restarts,
// and the whole set can be saved to / loaded from a JSON file so an AI agent
// can carry its analysis notes between sessions.
struct Note {
    std::string module;  // module file name, e.g. "target.exe"
    uint64_t rva = 0;
    std::string label;
    std::string comment;
};

class Notes {
public:
    // label is a plain identifier usable in expressions ("break my_loop")
    bool set_label(const std::string& module, uint64_t rva, const std::string& name,
                   std::string& err);
    void set_comment(const std::string& module, uint64_t rva, const std::string& text);
    void remove_label(const std::string& module, uint64_t rva);
    void remove_comment(const std::string& module, uint64_t rva);
    void clear();

    bool lookup_label(const std::string& name, std::string& module, uint64_t& rva) const;
    const Note* find(const std::string& module, uint64_t rva) const;

    std::vector<Note> all() const;
    size_t count() const { return count_; }
    Json to_json() const;

    bool save(const std::string& path, std::string& err) const;
    bool load(const std::string& path, std::string& err);

private:
    static std::string key(const std::string& module);
    void erase_if_empty(const std::string& module, uint64_t rva);

    // module(lower) -> rva -> note
    std::map<std::string, std::map<uint64_t, Note>> notes_;
    // label(lower) -> (module key, rva)
    std::map<std::string, std::pair<std::string, uint64_t>> labels_;
    size_t count_ = 0;
};

}  // namespace aj
