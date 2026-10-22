#pragma once
#include <windows.h>
#include <dbghelp.h>

#include <string>

namespace aj {

std::string last_error_text(DWORD err = ::GetLastError());

}  // namespace aj
