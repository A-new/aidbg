// Test target for the typed-expression / struct-layout features. Built with
// /Zi so the PDB carries full type information.
#include <cstdio>
#include <cstring>

struct Point {
    int x;
    int y;
    char label[16];
};

struct Node {
    int value;
    Point pos;
    Node* next;
    double weight;
};

Node g_head;
Node g_second;
Point g_origin;

__declspec(noinline) int total(int n) {
    int sum = 0;
    for (int i = 0; i < n; ++i) sum += g_head.value + i;
    return sum;
}

int main() {
    g_origin.x = 3;
    g_origin.y = 7;
    strcpy(g_origin.label, "origin");

    g_head.value = 100;
    g_head.pos = g_origin;
    g_head.next = &g_second;
    g_head.weight = 2.5;

    g_second.value = 200;
    g_second.pos.x = 11;
    g_second.pos.y = 22;
    strcpy(g_second.pos.label, "second");
    g_second.next = 0;
    g_second.weight = 3.5;

    int t = total(5);
    printf("total=%d head=%d second=%d\n", t, g_head.value, g_second.value);
    return 0;
}
