#include "engine/win_compat.h"

#include "util/strutil.h"

namespace aj {

std::string last_error_text(DWORD err) {
    if (err == 0) err = ::GetLastError();
    // FormatMessageA returns the system text in the ANSI code page; putting
    // those bytes straight into the JSON envelope produces invalid UTF-8 on a
    // non-English system. Ask for UTF-16 and convert.
    LPWSTR buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             (LPWSTR)&buf, 0, nullptr);
    std::string msg;
    if (n && buf) {
        msg = to_utf8(std::wstring(buf, n));
        LocalFree(buf);
        while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' '))
            msg.pop_back();
    } else {
        msg = "unknown error";
    }
    return fmt("win32 error %lu (%s)", err, msg.c_str());
}

}  // namespace aj
