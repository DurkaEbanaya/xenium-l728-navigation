.syntax unified
.cpu cortex-a7
.thumb
.section .text
.balign 4
.global highlight_image_original
.type highlight_image_original,%function
.thumb_func
highlight_image_original:
    push.w {r2,r3,r4,r5,r6,r7,r8,lr}
    mov r6,r2
    mov r4,r0
    ldr.w pc, 2f
    .balign 4
2:  .word 0x881ed5cd

.balign 4
.global highlight_string_original
.type highlight_string_original,%function
.thumb_func
highlight_string_original:
    push {r4,r5,r6,lr}
    movs r5,r1
    mov r4,r0
    beq 1f
    ldr.w pc, 2f
    .balign 4
2:  .word 0x881ed671
1:
    pop {r4,r5,r6,pc}

/* These are call-site adapters, not function-entry trampolines. The stock
 * renderer has already prepared its font/format/color arguments on stack. */
.balign 4
.global highlight_menu_text
.type highlight_menu_text,%function
.thumb_func
highlight_menu_text:
    ldrh.w ip,[r4,#0x96]
    cmp ip,r9
    bne 3f
    ldr ip,[sp,#4]
    tst.w ip,#0x1000
    bne 3f
    push {r0,r1,r2,r3,r4,lr}
    ldrh r0,[sp,#44]
    bl highlight_menu_color
    strh r0,[sp,#44]
    pop {r0,r1,r2,r3,r4,lr}
3:  ldr.w pc,4f
    .balign 4
4:  .word 0x880a328f

.balign 4
.global highlight_menu_scroll
.type highlight_menu_scroll,%function
.thumb_func
highlight_menu_scroll:
    push {r0,r1,r2,r3,r4,lr}
    ldrh r0,[sp,#44]
    bl highlight_menu_color
    strh r0,[sp,#44]
    pop {r0,r1,r2,r3,r4,lr}
    ldr.w pc,5f
    .balign 4
5:  .word 0x880a34cd
