.syntax unified
.cpu cortex-a7
.thumb
.section .text,"ax",%progbits
.global sos_wrapper, original_key_entry
.thumb_func
sos_wrapper:
    cmp r1, #0x64
    bne original_key_entry
    movw ip, #0xfa00
    cmp r0, ip
    beq sos_event
    adds ip, #0x100
    cmp r0, ip
    beq sos_event
    adds ip, #0x100
    cmp r0, ip
    beq sos_event
    adds ip, #0x100
    cmp r0, ip
    beq sos_event
    adds ip, #0x100
    cmp r0, ip
    bne original_key_entry
sos_event:
    @ Keep the same input/backlight/deferred-lock service as stock, but do
    @ not send any SOS event to windows or the default emergency handler.
    push {r0-r8, lr}
.ifdef SOS_NO_FLASH
    @ Slot/timer release cleanup already ran in the hardware-message caller.
    @ Suppress only wake-capable servicing of an ordinary lock's trailing
    @ SOS events; the next FA must still wake and toggle normally.
    movw r1, #0xfa00
    cmp r0, r1
    beq sos_service
    movs r0, #0x52
    ldr ip, =0x8809df7f
    blx ip
    cbz r0, sos_service
    ldr ip, =0x881aed45
    blx ip
    cbz r0, sos_return
sos_service:
    ldr r0, [sp]
    ldr r1, [sp, #4]
.endif
    ldr ip, =0x881768e7
    blx ip
    ldr r0, [sp]
    movw r1, #0xfa00
    cmp r0, r1
    bne sos_return
    @ Hardware FA is admitted once by the stock three-slot registration.
    @ The slot is cleared upstream on FB/FD, before this hook is entered.
    movs r0, #0x52
    ldr ip, =0x8809df7f
    blx ip
    cbz r0, sos_lock
    ldr ip, =0x881aed45 @ Mode 3 is a configuration preview, not keylock.
    blx ip
    cbnz r0, sos_return
    movs r0, #2
    ldr ip, =0x881aed55 @ Match the ordinary unlock path's mode transition.
    blx ip
    ldr ip, =0x881aeeed @ Resume services paused by the ordinary lock UI.
    blx ip
    ldr ip, =0x881aee4b @ Managed close delivers F022 and cancels UI timers.
    blx ip
.ifdef SOS_SCREEN
    ldr ip, =0x88176887 @ Normal MMI wake/backlight scheduling after close.
    blx ip
.endif
    b sos_return
sos_lock:
    ldr ip, =0x881aedbf @ Ordinary lock constructor retains its own guards.
    blx ip
sos_return:
.ifdef SOS_SCREEN
    @ Key-up/long/repeat input servicing may turn light on again. Enforce
    @ screen-off only when an ordinary lock window really exists.
    movs r0, #0x52
    ldr ip, =0x8809df7f
    blx ip
    cbz r0, screen_done
    ldr ip, =0x881aed45
    blx ip
    cbnz r0, screen_done
    ldr r0, =0x81704114
    ldr r0, [r0, #0x24]
    cmp r0, #2
    beq screen_done
    movs r0, #0
    ldr ip, =0x8817707b @ Stock close-all-light path; 0 forbids new lock UI.
    blx ip
screen_done:
.endif
    pop {r0-r8, lr}
    movs r0, #1
    bx lr
.thumb_func
original_key_entry:
    @ Relocated eight bytes, verified against the installed firmware.
    push {r4, r5, r6, r7, lr}
    sub sp, #0x34
    mov r4, r1
    movs r1, #0x28
    ldr ip, =0x886a2a8d
    bx ip
.ltorg
