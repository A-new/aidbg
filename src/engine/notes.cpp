#include "engine/notes.h"

#include <fstream>
#include <sstream>

#include "util/json_parse.h"
#include "util/strutil.h"

namespace aj {

namespace {

bool valid_label(const std::string& name) {
    if (name.empty() || name.size() > 128) return false;
    if (name[0] >= '0' && name[0] <= '9') return false;
    for (char c : name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '.' || c == '$' || c == '?' || c == '@';
        if (!ok) return false;
    }
    return true;
}

}  // namespace

std::string Notes::key(const std::string& module) {
    std::string m = to_lower(module);
    // normalize "c:\dir\mod.exe" to "mod.exe" so notes survive path changes
    size_t slash = m.find_last_of("\\/");
    if (slash != std::string::npos) m = m.substr(slash + 1);
    return m;
}

bool Notes::set_label(const std::string& module, uint64_t rva, const std::string& name,
                      std::string& err) {
    if (!valid_label(name)) {
        err = "invalid label (letters, digits, _ . $ ? @ ; must not start with a digit)";
        return false;
    }
    std::string k = key(module);
    std::string low = to_lower(name);
    // one label per address, one address per label
    auto it = labels_.find(low);
    if (it != labels_.end() && !(it->second.first == k && it->second.second == rva)) {
        err = "label already used at " + it->second.first + "+" + hex8(it->second.second);
        return false;
    }
    auto& slot = notes_[k][rva];
    if (slot.label.empty() && slot.comment.empty()) count_++;  // brand new note
    if (!slot.label.empty()) labels_.erase(to_lower(slot.label));
    slot.module = k;
    slot.rva = rva;
    slot.label = name;
    labels_[low] = {k, rva};
    return true;
}

void Notes::set_comment(const std::string& module, uint64_t rva, const std::string& text) {
    std::string k = key(module);
    auto& slot = notes_[k][rva];
    if (slot.label.empty() && slot.comment.empty()) {
        slot.module = k;
        slot.rva = rva;
        count_++;
    }
    slot.comment = text;
    if (slot.label.empty() && slot.comment.empty()) erase_if_empty(k, rva);
}

void Notes::remove_label(const std::string& module, uint64_t rva) {
    std::string k = key(module);
    auto mit = notes_.find(k);
    if (mit == notes_.end()) return;
    auto nit = mit->second.find(rva);
    if (nit == mit->second.end()) return;
    if (!nit->second.label.empty()) labels_.erase(to_lower(nit->second.label));
    nit->second.label.clear();
    erase_if_empty(k, rva);
}

void Notes::remove_comment(const std::string& module, uint64_t rva) {
    std::string k = key(module);
    auto mit = notes_.find(k);
    if (mit == notes_.end()) return;
    auto nit = mit->second.find(rva);
    if (nit == mit->second.end()) return;
    nit->second.comment.clear();
    erase_if_empty(k, rva);
}

void Notes::erase_if_empty(const std::string& module, uint64_t rva) {
    auto mit = notes_.find(module);
    if (mit == notes_.end()) return;
    auto nit = mit->second.find(rva);
    if (nit != mit->second.end() && nit->second.label.empty() && nit->second.comment.empty()) {
        mit->second.erase(nit);
        if (count_) count_--;
    }
    if (mit->second.empty()) notes_.erase(mit);
}

void Notes::clear() {
    notes_.clear();
    labels_.clear();
    count_ = 0;
}

bool Notes::lookup_label(const std::string& name, std::string& module, uint64_t& rva) const {
    auto it = labels_.find(to_lower(name));
    if (it == labels_.end()) return false;
    module = it->second.first;
    rva = it->second.second;
    return true;
}

const Note* Notes::find(const std::string& module, uint64_t rva) const {
    auto mit = notes_.find(key(module));
    if (mit == notes_.end()) return nullptr;
    auto nit = mit->second.find(rva);
    return nit == mit->second.end() ? nullptr : &nit->second;
}

std::vector<Note> Notes::all() const {
    std::vector<Note> out;
    for (const auto& mkv : notes_)
        for (const auto& nkv : mkv.second) out.push_back(nkv.second);
    return out;
}

Json Notes::to_json() const {
    Json arr = Json::arr();
    for (const auto& n : all()) {
        Json j = Json::obj();
        j.set_str("module", n.module);
        j.set_hex("rva", n.rva);
        if (!n.label.empty()) j.set_str("label", n.label);
        if (!n.comment.empty()) j.set_str("comment", n.comment);
        arr.push(std::move(j));
    }
    return arr;
}

bool Notes::save(const std::string& path, std::string& err) const {
    Json doc = Json::obj();
    doc.set_str("format", "aidbg-notes-1");
    doc.set("notes", to_json());
    std::ofstream f(to_wide(path), std::ios::trunc);
    if (!f) {
        err = "cannot write " + path;
        return false;
    }
    f << doc.dump(1) << "\n";
    return true;
}

bool Notes::load(const std::string& path, std::string& err) {
    std::ifstream f(to_wide(path));
    if (!f) {
        err = "cannot open " + path;
        return false;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    Json doc;
    std::string perr;
    if (!json_parse(ss.str(), doc, perr)) {
        err = "parse error in " + path + ": " + perr;
        return false;
    }
    const Json& arr = doc.get("notes");
    if (arr.type() != Json::Type::Arr) {
        err = "no 'notes' array in " + path;
        return false;
    }
    size_t added = 0;
    for (size_t i = 0; i < arr.size(); ++i) {
        const Json& e = arr.at(i);
        std::string mod = e.get("module").as_str();
        if (mod.empty()) continue;
        uint64_t rva = e.get("rva").as_u();
        // rva may be stored as a hex string
        if (!rva) parse_u64(e.get("rva").as_str(), rva);
        std::string label = e.get("label").as_str();
        std::string comment = e.get("comment").as_str();
        if (!label.empty()) {
            std::string err2;
            if (!set_label(mod, rva, label, err2)) continue;
        }
        if (!comment.empty()) set_comment(mod, rva, comment);
        added++;
    }
    if (!added) err = "no usable notes in " + path;
    return added > 0;
}

}  // namespace aj
