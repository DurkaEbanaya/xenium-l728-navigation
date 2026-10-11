#include <stdint.h>
#define R(o) (*(volatile uint32_t *)(0x21a00000u + (o)))
#define CTRL ((volatile uint32_t *)0x11000u)
static int run(const uint16_t *inst, unsigned n, uint32_t cfg) {
    unsigned i;
    R(0) = 2;
    for (i = 0; i < n; i += 2)
        R(0x220 + i * 2) = inst[i] | ((uint32_t)(i + 1 < n ? inst[i + 1] : 0) << 16);
    R(4) = cfg;
    R(0x10) = 0x7f00;
    R(0) = 1;
    for (i = 0; i < 1000000; i++) {
        if (R(0x10) & 0x01000000) return 0;
    }
    return -1;
}
void helper(void) {
    uint32_t first = CTRL[0], count = CTRL[1], page, col;
    CTRL[2] = 0;
    CTRL[3] = 0;
    R(0xf8) = 0x3a;
    R(8) = 0x31ff;
    R(12) = 0x2101000b;
    R(0x200) = 0;
    R(0x208) = ~0u; R(0x20c) = ~0u;
    R(0x210) = ~0u; R(0x214) = ~0u;
    uint16_t config[] = {0x1f, 0xb0, 9, 0xe000, 0xf000};
    if (run(config, 5, 2)) { CTRL[3] = 3; return; }
    for (page = first; page < first + count; page++) {
        uint16_t load[] = {0x13, page >> 16, (page >> 8) & 255, page & 255,
                           0xe000, 0x0f, 0xc0, 0x1000, 0xe001, 0xf000};
        if (run(load, 10, 2)) { CTRL[3] = 1; break; }
        for (col = 0; col < 2112; col += 512) {
            unsigned n = 512;
            uint16_t cache[] = {0x6b, col >> 8, col & 255, 0x6000, 0x3200, 0xe000, 0xf000};
            R(8) = 0x3000 | (n - 1);
            R(0x204) = 0x80400000u + (page - first) * 2560 + col;
            if (run(cache, 7, 0x50)) { CTRL[3] = 2; break; }
        }
        if (CTRL[3]) break;
        CTRL[2]++;
    }
    CTRL[4] = R(0x10);
    CTRL[5] = R(0);
}
