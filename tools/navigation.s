.syntax unified
.cpu cortex-a7
.thumb
.section .text,"ax",%progbits
.global list_wrapper, icon_wrapper, main_wrapper, matrix_wrapper, remap_event
.global contact_wrapper, search_contact_wrapper
.thumb_func
list_wrapper:
    push {r0, r2, r3, lr}
    bl remap_event
    pop {r0, r2, r3, lr}
    ldr ip, =0x881f1fdb
    bx ip
.thumb_func
icon_wrapper:
    push {r0, r2, r3, lr}
    bl remap_event
    pop {r0, r2, r3, lr}
    ldr ip, =0x880ce5d5
    bx ip
.thumb_func
main_wrapper:
    push {r0, r2, r3, lr}
    bl remap_event
    pop {r0, r2, r3, lr}
    ldr ip, =0x880d6dab
    bx ip
.thumb_func
matrix_wrapper:
    push {r0, r2, r3, lr}
    bl remap_event
    pop {r0, r2, r3, lr}
    ldr ip, =0x881102d5
    bx ip
.thumb_func
contact_wrapper:
    push {r0, r1, r2, r3, r4, r5, r6, lr}
    bl remap_event
    ldr r2, [sp, #4]
    cmp r1, r2
    beq contact_check_digit
    movw r2, #0xfa1b @ Key 5 maps to OK, without changing focus.
    cmp r1, r2
    bne contact_find_list
    str r1, [sp, #4]
    b contact_done
contact_find_list:
    mov r5, r1
    ldr r4, [sp]
    mov r0, r4
    ldr r1, =0x000d006f @ Entry-list tab list: window 0x000d004c + 0x23.
    ldr ip, =0x881ecba9 @ Get control handle by ID.
    blx ip
    cbnz r0, contact_remap
    mov r0, r4
    ldr r1, =0x000d0078 @ Most-used tab list: window 0x000d004c + 0x2c.
    ldr ip, =0x881ecba9
    blx ip
    cbz r0, contact_done
contact_remap:
    mov r1, r0
    mov r0, r4
    ldr ip, =0x881ecd65 @ Focus the list even if the search edit had focus.
    blx ip
    str r5, [sp, #4]
    b contact_done
contact_check_digit:
    ldr r2, [sp, #4]
    movw r3, #0xfa08
    cmp r2, r3
    blo contact_done
    adds r3, #10
    cmp r2, r3
    bhi contact_done
    b contact_consume
contact_consume:
    pop {r0, r1, r2, r3, r4, r5, r6, lr}
    movs r0, #1
    bx lr
contact_done:
    pop {r0, r1, r2, r3, r4, r5, r6, lr}
    ldr ip, =0x886bffcd
    bx ip
.thumb_func
search_contact_wrapper:
    push {r0, r1, r2, r3, r4, r5, r6, lr}
    bl remap_event
    ldr r2, [sp, #4]
    cmp r1, r2
    beq search_contact_check_digit
    movw r2, #0xfa1b @ Key 5 maps to the contact list's OK action.
    cmp r1, r2
    bne search_contact_find_list
    str r1, [sp, #4]
    b search_contact_done
search_contact_find_list:
    mov r5, r1
    ldr r4, [sp]
    mov r0, r4
    ldr r1, =0x000d00b8 @ Search list: edit ID 0x000d00b3 + 5.
    ldr ip, =0x881ecba9
    blx ip
    cbz r0, search_contact_done
    mov r1, r0
    mov r0, r4
    ldr ip, =0x881ecd65
    blx ip
    str r5, [sp, #4]
    b search_contact_done
search_contact_check_digit:
    ldr r2, [sp, #4]
    movw r3, #0xfa08
    cmp r2, r3
    blo search_contact_done
    adds r3, #10
    cmp r2, r3
    bhi search_contact_done
    pop {r0, r1, r2, r3, r4, r5, r6, lr}
    movs r0, #1
    bx lr
search_contact_done:
    pop {r0, r1, r2, r3, r4, r5, r6, lr}
    ldr ip, =0x886c2ac3
    bx ip
.thumb_func
remap_event:
    @ Physical table: 0x32->logical9, 0x34->11, 0x36->13, 0x38->15.
    @ Logical arrows: up1, down2, left3, right4.
    @ Only ordinary key-down events; text controls do not call these wrappers.
    movw r2, #0xfa0c
    cmp r1, r2
    beq center_ok
    movw r2, #0xfa09
    cmp r1, r2
    beq up
    adds r2, #2
    cmp r1, r2
    beq left
    adds r2, #2
    cmp r1, r2
    beq right
    adds r2, #2
    cmp r1, r2
    beq down
    bx lr
up:
    movw r1, #0xfa01
    bx lr
left:
    movw r1, #0xfa03
    bx lr
right:
    movw r1, #0xfa04
    bx lr
down:
    movw r1, #0xfa02
    bx lr
center_ok:
    movw r1, #0xfa1b
    bx lr
.ltorg
