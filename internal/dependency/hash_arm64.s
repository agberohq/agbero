//go:build arm64 && !noasm

#include "textflag.h"

// func crc32HashAsm(p unsafe.Pointer, length int) uint64
// Uses ARMv8 CRC32CX instructions to process 8 bytes per cycle.
TEXT ·crc32HashAsm(SB), NOSPLIT, $0-24
    MOVD p+0(FP), R0
    MOVD length+8(FP), R1
    MOVW $0xFFFFFFFF, R2

loop8:
    CMP R1, $8
    BLT loop4
    MOVD (R0), R3
    CRC32CX R3, R2
    ADD $8, R0
    SUB $8, R1
    B loop8

loop4:
    CMP R1, $4
    BLT loop2
    MOVW (R0), R3
    CRC32CW R3, R2
    ADD $4, R0
    SUB $4, R1

loop2:
    CMP R1, $2
    BLT loop1
    MOVH (R0), R3
    CRC32CH R3, R2
    ADD $2, R0
    SUB $2, R1

loop1:
    CMP R1, $1
    BLT done
    MOVB (R0), R3
    CRC32CB R3, R2

done:
    MVN R2, R2
    UXTW R2, R2
    MOVD R2, R3
    LSL $32, R3
    ORR R3, R2
    MOVD R2, ret+16(FP)
    RET
