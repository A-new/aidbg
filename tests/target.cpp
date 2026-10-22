// Test target for aidbg end-to-end verification.
#include <cstdio>
#include <cstring>

static int g_counter = 0;
static char g_buffer[256];
static const char* g_message = "aidbg-test-marker";

__declspec(noinline) int accumulate(int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) {
        total += i * 3;
        g_counter = total;
    }
    return total;
}

__declspec(noinline) void fill_buffer() {
    for (int i = 0; i < 64; ++i) g_buffer[i] = (char)('A' + (i % 26));
}

__declspec(noinline) int level3(int x) { return x * 2 + 1; }
__declspec(noinline) int level2(int x) { return level3(x) + 7; }
__declspec(noinline) int level1(int x) { return level2(x) * 3; }

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    fill_buffer();
    for (int round = 0; round < 5; ++round) {
        int r = accumulate(10 + round);
        if (r < 0) break;
    }
    int deep = level1(11);
    g_counter += deep;
    return 0;
}
