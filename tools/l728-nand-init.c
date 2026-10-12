/* SRAM-only controller initialization for the separate L728 RAM helpers.
 * DRAM must already have been initialized by the FDL. No NAND commands.
 * Register values match the SPI-NAND prototype used for the earlier patch.
 */
#include <stdint.h>
#define M(a) (*(volatile uint32_t *)(a))
#define R(o) M(0x21a00000u + (o))
#define CTRL ((volatile uint32_t *)0x11000u)
void helper(void) {
    M(0x20e00000u) |= 0x200;
    M(0x20e00004u) &= ~0x70u;
    M(0x20e00000u) &= ~0xd00u;
    M(0x402e0000u) |= 0x100000;
    M(0x402e00b0u) |= 0x1000;
    M(0x402a0024u) |= 0x1000;
    for (unsigned a = 0x402a0154; a < 0x402a0198; a += 4) M(a) = 0;
    for (unsigned a = 0x402a0554; a < 0x402a0598; a += 4) M(a) = 0x300000;
    M(0x402a0558u) = 0x301000;
    M(0x402a0574u) = 0x300080;
    M(0x21500060u) = 0x308;
    M(0x21500024u) = 2;
    R(0x14) = 0x3a493146; R(0x18) = 0x192a0000;
    R(0x34) = 0x81000000; R(0x38) = 0x00030005;
    R(0xb0) = 0x00001004; R(0xb4) = 0x00001004;
    R(0xb8) = 0x00004013; R(0xbc) = 0x00400010;
    R(0xdc) = 6; R(0xe0) = 0x100; R(0xe4) = 0x100;
    R(0xe8) = 0xbf; R(0x180) = 0x680; R(0x188) = 3;
    R(0x12c) = 0x548a;
    R(8) = 0x0a1f33ff; R(12) = 0x2101000b;
    R(0xec) = 0x00040002; R(0xf8) |= 2;
    CTRL[0] = 0x4c373238;
    CTRL[1] = R(0x14); CTRL[2] = R(0x18);
    CTRL[3] = R(8); CTRL[4] = R(12); CTRL[5] = R(0xdc);
}
