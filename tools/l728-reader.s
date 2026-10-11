.syntax unified
.arch armv7-a
.section .entry,"ax",%progbits
.arm
.global _start
_start:
.space 0x200
ldr r12, 1f
bx r12
1: .word helper
