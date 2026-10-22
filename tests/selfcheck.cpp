// Self-integrity probe: hashes its own image file at startup and compares it
// against an expected CRC32 (given on the command line). This is exactly the
// "file self check" scenario that a patched-copy launch would fail: the probe
// must see its own on-disk bytes unchanged while its image is loaded at the PE
// ImageBase.
//
//   selfcheck.exe <expected_crc32_hex> <report_file>
//
// Writes "key=value" lines to the report file; exit code 0 = self check passed.
#include <windows.h>
#include <stdio.h>

static unsigned crc32(const unsigned char* data, size_t n) {
    unsigned crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        crc ^= data[i];
        for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("usage: selfcheck.exe <expected_crc32_hex> <report_file>\n");
        return 2;
    }
    unsigned expected = (unsigned)strtoul(argv[1], nullptr, 16);
    FILE* f = fopen(argv[2], "w");
    if (!f) return 2;

    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    unsigned actual = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(f, "file_error=%lu\n", GetLastError());
        fclose(f);
        return 2;
    }
    DWORD size = GetFileSize(h, nullptr), got = 0;
    unsigned char* buf = (unsigned char*)malloc(size);
    ReadFile(h, buf, size, &got, nullptr);
    CloseHandle(h);
    actual = crc32(buf, got);
    free(buf);

    HMODULE base = GetModuleHandleW(nullptr);
    fprintf(f, "path=%ls\n", path);
    fprintf(f, "loaded_base=0x%p\n", (void*)base);
    fprintf(f, "file_crc=0x%08X\n", actual);
    fprintf(f, "expected_crc=0x%08X\n", expected);
    int ok = (actual == expected);
    fprintf(f, "self_check=%s\n", ok ? "PASS" : "FAIL");
    fclose(f);
    printf("self_check=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
