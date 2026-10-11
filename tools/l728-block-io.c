/* Model-specific block replacement helper for the six navigation blocks.
 * Input/output: 64 packed pages (2048+64) at 0x80400000.
 * CTRL: magic, operation (0 read / 1 erase+program), block, done, error,
 *       error page, NAND status, controller INT, original protection.
 * Mutating operations require magic 0x4c373238 and an explicit block allowlist.
 */
#include <stdint.h>
#define R(o) (*(volatile uint32_t *)(0x21a00000u + (o)))
#define CTRL ((volatile uint32_t *)0x11000u)
#define DATA ((volatile uint8_t *)0x80400000u)
static int run(const uint16_t *inst, unsigned n, uint32_t cfg) {
    R(0) = 2;
    for (unsigned i = 0; i < n; i += 2)
        R(0x220 + i * 2) = inst[i] | ((uint32_t)(i + 1 < n ? inst[i + 1] : 0) << 16);
    R(4) = cfg;
    R(0x10) = 0x7f00;
    R(0) = 1;
    for (unsigned i = 0; i < 10000000; i++)
        if (R(0x10) & 0x01000000) {
            if (R(0x10) & 0x0e000000) return -2;
            return 0;
        }
    return -1;
}
static int feature(unsigned reg, unsigned value) {
    uint16_t inst[] = {0x1f, reg, value, 0xe000, 0xf000};
    return run(inst, 5, 2);
}
static int get_feature(unsigned reg, uint32_t *value) {
    uint16_t inst[] = {0x0f, reg, 0x1000, 0xe000, 0xf000};
    int rc = run(inst, 5, 2);
    *value = R(0x19c) & 255;
    return rc;
}
static int simple(unsigned opcode) {
    uint16_t inst[] = {opcode, 0xe000, 0xf000};
    return run(inst, 3, 0x8002);
}
static int row_cmd(unsigned opcode, unsigned page) {
    uint16_t inst[] = {opcode, page >> 16, (page >> 8) & 255, page & 255,
                       0xe000, 0x0f, 0xc0, 0x1000, 0xe201, 0xf000};
    int rc = run(inst, 10, 0x8002);
    uint32_t status;
    if (!rc) rc = get_feature(0xc0, &status);
    else status = ~0u;
    CTRL[6] = status;
    if (!rc && (status & 0x0d)) rc = -3;
    return rc;
}
static int cache_load(uint32_t base) {
    for (unsigned i = 0; i < 5; i++) {
        unsigned col = i == 4 ? 1600 : i * 512;
        uint16_t inst[] = {i ? 0x34 : 0x32, col >> 8, col & 255, 0x2200, 0xe000, 0xf000};
        R(8) = 0x31ff;
        R(0x204) = base + col;
        int rc = run(inst, 6, 0x8150);
        if (rc) return rc;
    }
    return 0;
}
static int read_page(unsigned page, uint32_t base) {
    int rc = row_cmd(0x13, page);
    if (rc) return rc;
    for (unsigned i = 0; i < 5; i++) {
        unsigned col = i == 4 ? 1600 : i * 512;
        uint16_t inst[] = {0x6b, col >> 8, col & 255, 0x6000, 0x3200, 0xe000, 0xf000};
        R(8) = 0x31ff;
        R(0x204) = base + col;
        rc = run(inst, 7, 0x50);
        if (rc) return rc;
    }
    return 0;
}
static int allowed(unsigned block) {
    return block == 0x13d || block == 0x143 || block == 0x145 ||
           block == 0x14c || block == 0x17a || block == 0x17c;
}
void helper(void) {
    unsigned magic = CTRL[0], operation = CTRL[1], block = CTRL[2];
    uint32_t protection = 0;
    int rc = 0;
    CTRL[3] = 0; CTRL[4] = 0; CTRL[5] = 0;
    CTRL[6] = 0; CTRL[7] = 0; CTRL[8] = 0;
    if (magic != 0x4c373238 || operation > 1 || !allowed(block)) {
        CTRL[4] = 1; return;
    }
    *(volatile uint32_t *)0x21500060 = 0x308;
    R(0xf8) = 0x3a; R(8) = 0x31ff; R(12) = 0;
    R(0x200) = 0;
    R(0x208) = ~0u; R(0x20c) = ~0u;
    R(0x210) = ~0u; R(0x214) = ~0u;
    if (feature(0xb0, 9)) { CTRL[4] = 2; return; }
    if (operation) {
        if (get_feature(0xa0, &protection)) { CTRL[4] = 3; return; }
        CTRL[8] = protection;
        if (feature(0xa0, 0)) { CTRL[4] = 4; return; }
        rc = simple(6);
        if (!rc) rc = row_cmd(0xd8, block * 64);
        if (rc) { CTRL[4] = 5; goto finish; }
    }
    for (unsigned page = 0; page < 64; page++) {
        uint32_t base = 0x80400000 + page * 2112;
        if (operation) {
            unsigned erased = 1;
            for (unsigned i = 0; i < 2112; i++)
                if (DATA[page * 2112 + i] != 255) { erased = 0; break; }
            if (erased) { CTRL[3]++; continue; }
            rc = simple(6);
            if (!rc) rc = cache_load(base);
            if (!rc) rc = row_cmd(0x10, block * 64 + page);
        } else rc = read_page(block * 64 + page, base);
        if (rc) { CTRL[4] = operation ? 6 : 7; CTRL[5] = page; break; }
        CTRL[3]++;
    }
finish:
    CTRL[7] = R(0x10);
    if (operation) {
        int disabled = simple(4);
        int restored = feature(0xa0, protection);
        if (!CTRL[4] && (disabled || restored)) CTRL[4] = 8;
    }
}
