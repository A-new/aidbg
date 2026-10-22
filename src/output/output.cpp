#include "output/output.h"

#include <cstdio>
#include <iostream>

namespace aj {

Json SessionMeta::to_json() const {
    Json j = Json::obj();
    j.set_bool("active", active);
    if (active || pid) j.set_u("pid", pid);
    if (tid) j.set_u("tid", tid);
    j.set_str("state", state);
    if (!stop_reason.empty()) j.set_str("stop_reason", stop_reason);
    if (!rip.empty()) j.set_str("rip", rip);
    if (!arch.empty()) j.set_str("arch", arch);
    if (process_count > 1) j.set_u("processes", process_count);
    if (!detail.empty()) j.set_str("detail", detail);
    return j;
}

Output& Output::instance() {
    static Output o;
    return o;
}

void Output::emit(const std::string& cmd, const CmdResult& r, const SessionMeta& meta) {
    if (quiet_) return;
    if (json_) {
        Json j = Json::obj();
        j.set_bool("ok", r.ok);
        j.set_str("cmd", cmd);
        if (r.ok) {
            j.set("data", r.data);
        } else {
            Json e = Json::obj();
            e.set_str("code", r.err_code);
            e.set_str("message", r.err_msg);
            j.set("error", e);
            if (!r.data.is_null()) j.set("data", r.data);
        }
        j.set("session", meta.to_json());
        std::string line = j.dump(indent_);
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    } else {
        if (!r.text.empty()) {
            std::fwrite(r.text.data(), 1, r.text.size(), stdout);
            if (r.text.back() != '\n') std::fputc('\n', stdout);
        }
        if (!r.ok) {
            std::fprintf(stdout, "[error] %s: %s\n", r.err_code.c_str(), r.err_msg.c_str());
        }
        std::fflush(stdout);
    }
}

void Output::event(const std::string& kind, const std::string& text, Json data) {
    if (quiet_) return;
    if (json_) {
        Json j = Json::obj();
        j.set_str("kind", "event");
        j.set_str("event", kind);
        j.set_str("text", text);
        if (!data.is_null()) j.set("data", data);
        std::string line = j.dump(indent_);
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    } else {
        std::fprintf(stdout, "[%s] %s\n", kind.c_str(), text.c_str());
        std::fflush(stdout);
    }
}

}  // namespace aj
