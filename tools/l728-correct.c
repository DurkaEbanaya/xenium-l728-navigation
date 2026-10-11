#include <stdint.h>
#define CTRL ((volatile uint32_t *)0x11000u)
struct params {
    uint16_t spare_size, ecc_pos, info_size, info_pos;
    uint8_t ecc_mode, padding[3];
    uint32_t main_addr, spare_addr, main_size;
};
void helper(void) {
    int (*decode)(struct params *) = (void *)0xffff35ddu;
    void (*poly_init)(unsigned) = (void *)0xffff37e1u;
    unsigned pages = CTRL[1];
    CTRL[2] = 0; CTRL[3] = 0; CTRL[4] = 0; CTRL[5] = 0;
    poly_init(0);
    *(volatile uint32_t *)0x21a00038 = 0;
    for (unsigned i = 0; i < pages * 2; i++) {
        uint32_t base = 0x80400000u + (i / 2) * 2112;
        uint32_t main = base + (i & 1) * 1024;
        uint32_t spare = base + 2048 + (i & 1) * 32;
        unsigned erased = 1;
        for (unsigned j = 0; j < 1024; j++)
            if (((volatile uint8_t *)main)[j] != 255) { erased = 0; break; }
        if (erased) for (unsigned j = 0; j < 32; j++)
            if (((volatile uint8_t *)spare)[j] != 255) { erased = 0; break; }
        if (erased) { CTRL[4]++; CTRL[2]++; continue; }
        struct params p = {32, 4, 0, 0, 4, {0, 0, 0}, main, spare, 1024};
        int rc = decode(&p);
        if (rc) {
            if (!CTRL[3]) CTRL[5] = i;
            CTRL[3]++;
        }
        CTRL[2]++;
    }
}
