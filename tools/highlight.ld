OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(highlight_display)
SECTIONS {
 . = PAYLOAD_ADDRESS;
 .payload : { *(.text*) *(.rodata*) }
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) }
 ASSERT(SIZEOF(.data) == 0, "mutable data must live in allocated RAM")
 ASSERT(SIZEOF(.bss) == 0, "mutable data must live in allocated RAM")
}
