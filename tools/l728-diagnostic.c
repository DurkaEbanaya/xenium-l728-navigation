/* Read-only NAND diagnostics and ECC generation/correction in RAM.
 * No write-enable, program-execute or erase opcode is used here.
 * Requires the L728 FDL with DRAM already initialized.
 */
#include <stdint.h>
#define R(o) (*(volatile uint32_t *)(0x21a00000u + (o)))
#define CTRL ((volatile uint32_t *)0x11000u)
#define BUF ((volatile uint8_t *)0x80400000u)
struct params {
    uint16_t spare_size, ecc_pos, info_size, info_pos;
    uint8_t ecc_mode, padding[3];
    uint32_t main_addr, spare_addr, main_size;
};
struct dma_params {
    uint32_t main_addr, spare_addr;
    uint8_t main_on, spare_on, input, pad;
    uint16_t main_size, spare_size;
};
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
    void (*poly_init)(unsigned) = (void *)0xffff37e1u;
    int (*decode)(struct params *) = (void *)0xffff35ddu;
    int (*dma)(struct dma_params *) = (void *)0xffff34b5u;
    int (*ecc)(struct params *, unsigned) = (void *)0xffff357du;
    for (unsigned i = 0; i < 64; i++) CTRL[i] = 0;
    CTRL[0] = 0x4c373238;
    /* Keep the FDL's known-working PHY initialization. The BootROM entry
     * alone does not reproduce all controller setup after FDL startup. */
    *(volatile uint32_t *)0x20e00000 |= 0xb00;
    *(volatile uint32_t *)0x21500060 = 0x308;
    R(0xf8) = 0x3a;
    R(8) = 0x31ff;
    R(12) = 0x2101000b;
    R(0x200) = 0;
    R(0x208) = ~0u; R(0x20c) = ~0u;
    R(0x210) = ~0u; R(0x214) = ~0u;
    /* Linux SPI-NAND probes opcode-only, address, and dummy variants. */
    for (unsigned variant = 0; variant < 3; variant++) {
        uint16_t inst[6] = {0x9f, 0x3000, 0xe000, 0xf000, 0, 0};
        unsigned n = 4;
        if (variant) {
            inst[1] = variant == 1 ? 0 : 0x6000;
            inst[2] = 0x3000; inst[3] = 0xe000; inst[4] = 0xf000;
            n = 5;
        }
        for (unsigned i = 0; i < 512; i++) BUF[0x2000 + variant * 512 + i] = 0xee;
        R(0x204) = 0x80402000 + variant * 512;
        CTRL[8 + variant * 3] = run(inst, n, 0x50);
        CTRL[9 + variant * 3] = R(0x10);
        CTRL[10 + variant * 3] = R(0);
    }
    uint16_t config[] = {0x1f, 0xb0, 9, 0xe000, 0xf000};
    if (run(config, 5, 2)) { CTRL[1] = 1; return; }
    uint16_t load[] = {0x13, 0, 0, 0, 0xe000, 0x0f, 0xc0, 0x1000, 0xe001, 0xf000};
    if (run(load, 10, 2)) { CTRL[1] = 2; return; }
    for (unsigned col = 0; col < 2112; col += 512) {
        uint16_t cache[] = {0x6b, col >> 8, col & 255, 0x6000, 0x3200, 0xe000, 0xf000};
        R(8) = 0x31ff;
        R(0x204) = 0x80400000 + col;
        if (run(cache, 7, 0x50)) { CTRL[1] = 3; return; }
    }
    for (unsigned i = 0; i < 2112; i++) BUF[0x1000 + i] = BUF[i];
    *(volatile uint32_t *)0x21500060 = 8;
    poly_init(0);
    R(0x38) = 0;
    struct params p = {32, 4, 0, 0, 4, {0, 0, 0}, 0x80400000, 0x80400800, 1024};
    CTRL[2] = decode(&p);
    if (CTRL[2]) { CTRL[1] = 4; return; }
    /* Save corrected reference and generate ECC from its main bytes. */
    for (unsigned i = 0; i < 1024; i++) BUF[0x3000 + i] = BUF[i];
    for (unsigned i = 0; i < 32; i++) BUF[0x3400 + i] = BUF[2048 + i];
    struct dma_params d = {p.main_addr, p.spare_addr, 1, 1, 1, 0, 1024, 32};
    for (unsigned i = 4; i < 25; i++) BUF[2048 + i] = 0xff;
    CTRL[3] = dma(&d);
    if (CTRL[3]) { CTRL[1] = 5; return; }
    CTRL[4] = ecc(&p, 1);
    if (CTRL[4]) { CTRL[1] = 6; return; }
    d.input = 0;
    CTRL[5] = dma(&d);
    if (CTRL[5]) { CTRL[1] = 7; return; }
    for (unsigned i = 4; i < 25; i++)
        if (BUF[2048 + i] != BUF[0x3400 + i]) CTRL[6]++;
    /* Decode an intentionally altered RAM byte using newly generated ECC. */
    BUF[123] ^= 1;
    CTRL[7] = decode(&p);
    for (unsigned i = 0; i < 1024; i++)
        if (BUF[i] != BUF[0x3000 + i]) CTRL[20]++;
    CTRL[21] = 1;
}
