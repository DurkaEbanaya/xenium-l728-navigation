/* Generate host ECC for packed 2048+64 byte pages in DRAM, no NAND I/O. */
#include <stdint.h>
#define CTRL ((volatile uint32_t *)0x11000u)
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
void helper(void) {
    void (*poly_init)(unsigned) = (void *)0xffff37e1u;
    int (*dma)(struct dma_params *) = (void *)0xffff34b5u;
    int (*ecc)(struct params *, unsigned) = (void *)0xffff357du;
    unsigned pages = CTRL[1];
    CTRL[2] = 0; CTRL[3] = 0; CTRL[4] = 0;
    if (!pages || pages > 128) { CTRL[3] = 1; return; }
    *(volatile uint32_t *)0x21500060 = 8;
    poly_init(0);
    *(volatile uint32_t *)0x21a00038 = 0;
    for (unsigned i = 0; i < pages * 2; i++) {
        uint32_t base = 0x80400000 + (i / 2) * 2112;
        struct params p = {32, 4, 0, 0, 4, {0, 0, 0},
                           base + (i & 1) * 1024, base + 2048 + (i & 1) * 32, 1024};
        struct dma_params d = {p.main_addr, p.spare_addr, 1, 1, 1, 0, 1024, 32};
        int rc = dma(&d);
        if (!rc) rc = ecc(&p, 1);
        if (!rc) { d.input = 0; rc = dma(&d); }
        if (rc) { CTRL[3] = rc; CTRL[4] = i; return; }
        CTRL[2]++;
    }
}
