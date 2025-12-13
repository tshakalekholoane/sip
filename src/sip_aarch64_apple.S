#ifndef __aarch64__
  #error "this is an AArch64 program"
#endif

#ifndef __APPLE__
  #error "this is a Darwin program"
#endif

#ifndef SIP_C
  #define SIP_C 2
#endif

#ifndef SIP_D
  #define SIP_D 4
#endif

.macro  sipr    a, b, c, d
        add     \a, \a, \b
        add     \c, \c, \d
        ror     \b, \b, #64 - 13
        ror     \d, \d, #64 - 16
        eor     \b, \b, \a
        eor     \d, \d, \c
        ror     \a, \a, #32
        add     \c, \c, \b
        add     \a, \a, \d
        ror     \b, \b, #64 - 17
        ror     \d, \d, #64 - 21
        eor     \b, \b, \c
        eor     \d, \d, \a
        ror     \c, \c, #32
.endm

        .const

        .balign 16
Lc:
        .8byte  0x736f6d6570736575
        .8byte  0x646f72616e646f6d
        .8byte  0x6c7967656e657261
        .8byte  0x7465646279746573

        .balign 16
Lremainder_len:
        .skip   4
        .4byte  Lremainder_len_1 - Lremainder_len_1
        .4byte  Lremainder_len_2 - Lremainder_len_1
        .4byte  Lremainder_len_3 - Lremainder_len_1
        .4byte  Lremainder_len_4 - Lremainder_len_1
        .4byte  Lremainder_len_5 - Lremainder_len_1
        .4byte  Lremainder_len_6 - Lremainder_len_1
        .4byte  Lremainder_len_7 - Lremainder_len_1

        .text

        .globl  _sip_hash
_sip_hash:
        .cfi_startproc

        adrp    x9, Lc@PAGE
        add     x9, x9, Lc@PAGEOFF
        ldnp    x4, x5, [x9]
        ldnp    x6, x7, [x9, #16]

        eor     x4, x4, x0
        eor     x5, x5, x1
        eor     x6, x6, x0
        eor     x7, x7, x1

        and     x9, x3, #~7
        cbz     x9, Lremainder

        add     x9, x2, x9
Lchunk:
        ldr     x10, [x2], #8

        eor     x7, x7, x10
.rept   SIP_C
        sipr    x4, x5, x6, x7
.endr
        eor     x4, x4, x10

        cmp     x2, x9
        bne     Lchunk

Lremainder:
        lsl     x10, x3, #56
        and     x9, x3, #7
        cbz     x9, Lfinish

        adrp    x11, Lremainder_len@PAGE
        add     x11, x11, Lremainder_len@PAGEOFF

        lsl     x12, x9, #2
        ldr     w13, [x11, x12]
        adr     x14, Lremainder_len_1
        add     x14, x14, x13
        br      x14

Lremainder_len_1:
        ldrb    w12, [x2]
        orr     x10, x10, x12
        b       Lfinish

Lremainder_len_2:
        ldrh    w12, [x2]
        orr     x10, x10, x12
        b       Lfinish

Lremainder_len_3:
        ldrh    w12, [x2]
        ldrb    w13, [x2, #2]
        bfi     x12, x13, #16, #8
        orr     x10, x10, x12
        b       Lfinish

Lremainder_len_4:
        ldr     w12, [x2]
        orr     x10, x10, x12
        b       Lfinish

Lremainder_len_5:
        ldr     w12, [x2]
        ldrb    w13, [x2, #4]
        bfi     x12, x13, #32, #8
        orr     x10, x10, x12
        b       Lfinish

Lremainder_len_6:
        ldr     w12, [x2]
        ldrh    w13, [x2, #4]
        bfi     x12, x13, #32, #16
        orr     x10, x10, x12
        b       Lfinish

Lremainder_len_7:
        ldr     w12, [x2]
        ldr     w13, [x2, #3]
        bfi     x12, x13, #24, #32
        orr     x10, x10, x12

Lfinish:
        eor     x7, x7, x10
.rept   SIP_C
        sipr    x4, x5, x6, x7
.endr
        eor     x4, x4, x10

        eor     x6, x6, #0xff

.rept   SIP_D
        sipr    x4, x5, x6, x7
.endr

        eor     x0, x4, x5
        eor     x6, x6, x7
        eor     x0, x0, x6

        ret

        .cfi_endproc

.subsections_via_symbols

// vim: filetype=asm
