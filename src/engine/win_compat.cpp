#include "engine/win_compat.h"

#include "util/strutil.h"

namespace aj {

std::string last_error_text(DWORD err) {
    if (err == 0) err = ::GetLastError();
    LPSTR buf = nullptr;
    DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             (LPSTR)&buf, 0, nullptr);
    std::string msg;
    if (n && buf) {
        msg.assign(buf, n);
        LocalFree(buf);
        while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' '))
            msg.pop_back();
    } else {
        msg = "unknown error";
    }
    return fmt("win32 error %lu (%s)", err, msg.c_str());
}

}  // namespace aj
