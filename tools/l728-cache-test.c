/* Verify SPI-NAND volatile page-cache loading, WITHOUT program or erase.
 * Buffers: input 0x80400000 (2112 bytes), readback 0x80402000 (2560).
 * This helper issues write-enable only for cache-load and write-disable
 * before returning. There is no PROGRAM EXECUTE (10) or BLOCK ERASE (d8).
 */
#include <stdint.h>
#define R(o) (*(volatile uint32_t *)(0x21a00000u + (o)))
#define CTRL ((volatile uint32_t *)0x11000u)
static int run(const uint16_t *inst, unsigned n, uint32_t cfg) {
    R(0) = 2;
    for (unsigned i = 0; i < n; i += 2)
        R(0x220 + i * 2) = inst[i] | ((uint32_t)(i + 1 < n ? inst[i + 1] : 0) << 16);
    R(4) = cfg;
    R(0x10) = 0x7f00;
    R(0) = 1;
    for (unsigned i = 0; i < 1000000; i++)
        if (R(0x10) & 0x01000000) return 0;
    return -1;
}
void helper(void) {
    unsigned completed = 0, failed = 0;
    *(volatile uint32_t *)0x21500060 = 0x308;
    R(0xf8) = 0x3a;
    R(8) = 0x31ff; R(12) = 0;
    R(0x200) = 0;
    R(0x208) = ~0u; R(0x20c) = ~0u;
    R(0x210) = ~0u; R(0x214) = ~0u;
    uint16_t config[] = {0x1f, 0xb0, 9, 0xe000, 0xf000};
    uint16_t enable[] = {6, 0xe000, 0xf000};
    uint16_t disable[] = {4, 0xe000, 0xf000};
    if (run(config, 5, 2) || run(enable, 3, 2)) { failed = 1; goto finish; }
    for (unsigned i = 0; i < 5; i++) {
        unsigned col = i == 4 ? 1600 : i * 512;
        uint16_t load[] = {i ? 0x34 : 0x32, col >> 8, col & 255, 0x2200, 0xe000, 0xf000};
        R(8) = 0x31ff;
        R(0x204) = 0x80400000 + col;
        if (run(load, 6, 0x8150)) { failed = 2 + i; goto finish; }
        completed++;
    }
    for (unsigned i = 0; i < 5; i++) {
        unsigned col = i == 4 ? 1600 : i * 512;
        uint16_t read[] = {0x6b, col >> 8, col & 255, 0x6000, 0x3200, 0xe000, 0xf000};
        R(8) = 0x31ff;
        R(0x204) = 0x80402000 + i * 512;
        if (run(read, 7, 0x50)) { failed = 7 + i; goto finish; }
        completed++;
    }
finish:
    CTRL[0] = 0x43414348; CTRL[1] = completed; CTRL[2] = failed;
    CTRL[3] = R(0x10); CTRL[4] = R(0);
    CTRL[5] = run(disable, 3, 2);
}
