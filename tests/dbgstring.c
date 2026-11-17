// Test target for debug-string normalisation. Emits three flavours of
// OutputDebugString so aidbg's JSONL contract can be checked: an already-UTF-8
// narrow string, an ANSI-code-page narrow string (the classic case that used
// to arrive as invalid UTF-8) and a UTF-16 string via the fUnicode flag.
#include <windows.h>

static void emit_ansi(const wchar_t* text) {
    int n = WideCharToMultiByte(CP_ACP, 0, text, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return;
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n);
    if (!buf) return;
    WideCharToMultiByte(CP_ACP, 0, text, -1, buf, n, NULL, NULL);
    OutputDebugStringA(buf);
    HeapFree(GetProcessHeap(), 0, buf);
}

int main(void) {
    // narrow literal: UTF-8 because the test is built with /utf-8
    OutputDebugStringA("UTF8 未指定的错误");
    // narrow bytes in the ANSI code page, as most MSVC targets produce them
    emit_ansi(L"ANSI 未指定的错误");
    // the wide variant sets OUTPUT_DEBUG_STRING_INFO.fUnicode
    OutputDebugStringW(L"UNICODE 未指定的错误");
    return 0;
}
