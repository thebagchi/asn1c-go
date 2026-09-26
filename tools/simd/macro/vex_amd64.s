#include "textflag.h"
#include "vex_amd64.h"

// Kernels that exist only to be compared against each other.
//
// Each operation appears twice, once written as a Go mnemonic and once built by the macros
// in vex_amd64.h, so the test can run both over the same input and check that the encoder
// agrees with the assembler. The pairs cover both VEX forms and all three escape maps,
// because those are the fields the encoder computes rather than copies.
//
// The last two have no Go mnemonic at all, which is the point of the header.

// LOAD_PAIR brings the two inputs into the low registers and leaves the output pointer in
// AX. Every kernel here takes the same three pointers, so the prologue is written once.
#define LOAD_PAIR(a, b)   \
	MOVQ dst+0(FP), AX    \
	MOVQ lhs+8(FP), BX    \
	MOVQ rhs+16(FP), CX   \
	VMOVDQU (BX), a       \
	VMOVDQU (CX), b

// func _AsmAdd(dst, lhs, rhs *byte)
TEXT ·_AsmAdd(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VPADDB  Y1, Y0, Y2
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _VexAdd(dst, lhs, rhs *byte)
TEXT ·_VexAdd(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VPADDB_256(YMM1, YMM0, YMM2)
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _AsmAddHigh(dst, lhs, rhs *byte)
TEXT ·_AsmAddHigh(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y8, Y9)
	VPADDB  Y9, Y8, Y10
	VMOVDQU Y10, (AX)
	VZEROUPPER
	RET

// func _VexAddHigh(dst, lhs, rhs *byte)
//
// The registers above 7 are the case that matters: they are encoded by clearing a bit in
// the VEX prefix rather than by setting one in ModRM, so an encoder that inverts them
// wrongly still emits a valid instruction naming the wrong register.
TEXT ·_VexAddHigh(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y8, Y9)
	VPADDB_256(YMM9, YMM8, YMM10)
	VMOVDQU Y10, (AX)
	VZEROUPPER
	RET

// func _AsmShuffle(dst, lhs, rhs *byte)
TEXT ·_AsmShuffle(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VPSHUFB Y1, Y0, Y2
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _VexShuffle(dst, lhs, rhs *byte)
//
// VPSHUFB is on the 0F38 escape map rather than 0F, which is a different value in the same
// prefix byte that carries the inverted register bits.
TEXT ·_VexShuffle(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VPSHUFB_256(YMM1, YMM0, YMM2)
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _AsmXor(dst, lhs, rhs *byte)
TEXT ·_AsmXor(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VPXOR   Y1, Y0, Y2
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _VexXor(dst, lhs, rhs *byte)
//
// Built through the two-byte VEX form, which lays the fields out differently from the
// three-byte one and is the encoding Go's own assembler picks here.
TEXT ·_VexXor(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VPXOR_256(YMM1, YMM0, YMM2)
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _AsmAffine(dst, lhs, rhs *byte)
TEXT ·_AsmAffine(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VGF2P8AFFINEQB $0x00, Y1, Y0, Y2
	VMOVDQU        Y2, (AX)
	VZEROUPPER
	RET

// func _VexAffine(dst, lhs, rhs *byte)
//
// GF2P8AFFINEQB applies the 8x8 bit matrix in each qword of rhs to every byte of lhs. It is
// the longest encoding here - a three-byte VEX, an opcode on the 0F3A map, W1, and an
// immediate - so it exercises every field the macro computes at once.
TEXT ·_VexAffine(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VGF2P8AFFINEQB_256(0x00, YMM1, YMM0, YMM2)
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET

// func _VexAffineHigh(dst, lhs, rhs *byte)
TEXT ·_VexAffineHigh(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y8, Y9)
	VGF2P8AFFINEQB_256(0x00, YMM9, YMM8, YMM10)
	VMOVDQU Y10, (AX)
	VZEROUPPER
	RET

// func _VexMul(dst, lhs, rhs *byte)
//
// GF2P8MULB multiplies bytes in GF(2^8). Also unspellable in Go.
TEXT ·_VexMul(SB), NOSPLIT, $0-24
	LOAD_PAIR(Y0, Y1)
	VGF2P8MULB_256(YMM1, YMM0, YMM2)
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET
