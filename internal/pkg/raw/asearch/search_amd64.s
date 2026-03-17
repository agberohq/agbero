//go:build amd64 && !noasm

#include "textflag.h"

// func linearSearchAsm(p unsafe.Pointer, length int, target uint64) int
// Executes a rapid linear scan over the provided array segment.
TEXT ·linearSearchAsm(SB), NOSPLIT, $0-32
    MOVQ p+0(FP), R8
    MOVQ length+8(FP), R9
    MOVQ target+16(FP), R10
    XORQ CX, CX
loop:
    CMPQ CX, R9
    JGE done_linear
    MOVQ (R8)(CX*8), R11
    CMPQ R11, R10
    JA found_linear
    INCQ CX
    JMP loop
found_linear:
    MOVQ CX, ret+24(FP)
    RET
done_linear:
    DECQ R9
    MOVQ R9, ret+24(FP)
    RET

// func sortedSearchAsm(p unsafe.Pointer, length int, target uint64) int
// Executes a binary search utilizing standard scalar instructions securely.
TEXT ·sortedSearchAsm(SB), NOSPLIT, $0-32
    MOVQ p+0(FP), R8
    MOVQ length+8(FP), R9
    MOVQ target+16(FP), R10
    XORQ CX, CX
    MOVQ R9, DX
bin_loop:
    CMPQ CX, DX
    JGE bin_done
    MOVQ CX, AX
    ADDQ DX, AX
    SHRQ $1, AX
    MOVQ (R8)(AX*8), R11
    CMPQ R11, R10
    JAE bin_greater
    INCQ AX
    MOVQ AX, CX
    JMP bin_loop
bin_greater:
    MOVQ AX, DX
    JMP bin_loop
bin_done:
    CMPQ CX, R9
    JNE bin_exit
    XORQ CX, CX
bin_exit:
    MOVQ CX, ret+24(FP)
    RET

