ENTRY(list_wrapper)
SECTIONS {
    . = 0x887e13c0;
    .text : { *(.text*) *(.rodata*) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) }
}
