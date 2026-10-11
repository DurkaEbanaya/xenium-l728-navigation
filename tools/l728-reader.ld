OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)
SECTIONS {
 .text 0x10000 : { *(.entry) *(.text*) *(.rodata*) }
 /DISCARD/ : { *(.ARM.exidx*) *(.comment*) }
 ASSERT(SIZEOF(.text) < 0x1000, "helper too large")
}
