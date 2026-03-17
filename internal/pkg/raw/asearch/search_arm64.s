//go:build arm64 && !noasm

#include "textflag.h"

// func linearSearchAsm(p unsafe.Pointer, length int, target uint64) int
// Executes a rapid linear scan over the provided array segment natively.
TEXT ·linearSearchAsm(SB), NOSPLIT, $0-32
    MOVD p+0(FP), R0
    MOVD length+8(FP), R1
    MOVD target+16(FP), R2
    MOVD $0, R3
loop:
    CMP R1, R3
    BGE done_linear
    MOVD (R0)(R3<<3), R4
    CMP R2, R4
    BHI found_linear
    ADD $1, R3
    B loop
found_linear:
    MOVD R3, ret+24(FP)
    RET
done_linear:
    SUB $1, R1
    MOVD R1, ret+24(FP)
    RET

// func sortedSearchAsm(p unsafe.Pointer, length int, target uint64) int
// Executes a binary search utilizing standard scalar instructions securely.
TEXT ·sortedSearchAsm(SB), NOSPLIT, $0-32
    MOVD p+0(FP), R0
    MOVD length+8(FP), R1
    MOVD target+16(FP), R2
    MOVD $0, R3
    MOVD R1, R4
bin_loop:
    CMP R4, R3
    BGE bin_done
    ADD R3, R4, R5
    LSR $1, R5
    MOVD (R0)(R5<<3), R6
    CMP R2, R6
    BHS bin_greater
    ADD $1, R5, R3
    B bin_loop
bin_greater:
    MOVD R5, R4
    B bin_loop
bin_done:
    CMP R3, R1
    BNE bin_exit
    MOVD $0, R3
bin_exit:
    MOVD R3, ret+24(FP)
    RET
