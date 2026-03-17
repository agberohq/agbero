//go:build amd64 && !noasm

#include "textflag.h"

// func crc32HashAsm(p unsafe.Pointer, length int) uint64
// Uses SSE4.2 CRC32 instructions to process 8 bytes per cycle.
TEXT ·crc32HashAsm(SB), NOSPLIT, $0-24
    MOVQ p+0(FP), SI
    MOVQ length+8(FP), CX
    MOVL $0xFFFFFFFF, AX

loop8:
    CMPQ CX, $8
    JL loop4
    CRC32Q (SI), AX
    ADDQ $8, SI
    SUBQ $8, CX
    JMP loop8

loop4:
    CMPQ CX, $4
    JL loop2
    CRC32L (SI), AX
    ADDQ $4, SI
    SUBQ $4, CX

loop2:
    CMPQ CX, $2
    JL loop1
    CRC32W (SI), AX
    ADDQ $2, SI
    SUBQ $2, CX

loop1:
    CMPQ CX, $1
    JL done
    CRC32B (SI), AX

done:
    NOTL AX
    MOVQ AX, DX
    SHLQ $32, DX
    ORQ DX, AX
    MOVQ AX, ret+16(FP)
    RET

    