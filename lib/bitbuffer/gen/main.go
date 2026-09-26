//go:build ignore

// Command gen builds the vectorised kernels for the mid-byte bulk shift, one per
// lane width.
//
// The three kernels compute the same thing - dst[i] = src[i]<<left | src[i+1]>>right
// for every byte of dst - at 16, 32 and 64 bytes per iteration. They differ only in
// instruction set, so one body is written once and each width supplies how it spells
// a load, a lane shift, a mask and a broadcast. That is what an avo program is for:
// the assembly is reviewed as the Go that produced it.
//
// Three rules the widths must not break, each learned by breaking it:
//
//   - The SSE2 kernel uses legacy encodings only and the other two use VEX or EVEX
//     only. Mixing them inside one function costs an AVX-SSE transition of roughly
//     70-300 cycles - golang/go#80835 - which is what makes the compiler's own simd
//     experiment slower than scalar.
//   - A kernel that touches a YMM or ZMM register ends with VZEROUPPER, or the next
//     legacy SSE instruction anywhere in the process stalls.
//   - The shift count travels to XMM once, before the loop, with the encoding of the
//     kernel it belongs to. Moving it per iteration is the other half of #80835.
//
// The processor probes that decide which kernel runs live in lib/cpu, with their
// own generator. Regenerate with "make generate".
package main

import (
	"strconv"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"

	"github.com/mmcloughlin/avo/reg"
)

// Lane widths in bytes, and the two constants the mask arithmetic needs.
const (
	LANES_SSE2    = 16
	LANES_AVX2    = 32
	LANES_AVX512  = 64
	BYTE_MASK     = 0xFF
	BROADCAST_ALL = 0
)

// _Width is one lane width of the kernel: its name, how many bytes it moves per
// iteration, and how it spells each step of the shared body.
type _Width struct {
	name      string
	lanes     int
	vector    func() reg.VecVirtual
	broadcast func(src reg.Register, dst reg.VecVirtual)
	count     func(src reg.Register, dst reg.VecVirtual)
	load      func(src Mem, dst reg.VecVirtual)
	store     func(src reg.VecVirtual, dst Mem)
	shl       func(count, value reg.VecVirtual)
	shr       func(count, value reg.VecVirtual)
	and       func(mask, value reg.VecVirtual)
	or        func(src, dst reg.VecVirtual)
	epilogue  func()
}

// main emits the three widths.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation, from tools/simd/shiftgen with the body
//     shared across widths
//   - 2026-09-24 01:40: the probes moved to lib/cpu, so this emits one file
func main() {
	ConstraintExpr("amd64")

	for _, width := range []*_Width{_SSE2(), _AVX2(), _AVX512()} {
		_Kernel(width)
	}

	Generate()
}

// _Kernel emits one width's TEXT block.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
//   - 2026-09-23 07:40: the loop tests at the bottom, one branch per
//     iteration instead of two
func _Kernel(width *_Width) {
	TEXT("_ShiftBlocks"+width.name, NOSPLIT, "func(dst, src []byte, left, right uint8)")
	Pragma("noescape")
	Doc(
		"_ShiftBlocks"+width.name+" writes dst[i] = src[i]<<left | src[i+1]>>right",
		"for every byte of dst, "+_Lanes(width)+" bytes per iteration.",
		"",
		"len(src) must be at least len(dst)+1 and len(dst) a multiple of "+_Lanes(width)+".",
	)

	dst := Load(Param("dst").Base(), GP64())
	n := Load(Param("dst").Len(), GP64())
	src := Load(Param("src").Base(), GP64())
	left := Load(Param("left"), GP32())
	right := Load(Param("right"), GP32())

	// There is no byte shift in any of these instruction sets, so each lane is
	// shifted as a 16-bit word and the bits dragged across the byte boundary
	// are masked off. The two masks are built once, in a general register,
	// then broadcast.
	hi, lo := width.vector(), width.vector()
	width.broadcast(_MaskHigh(left), hi)
	width.broadcast(_MaskLow(right), lo)

	shl, shr := XMM(), XMM()
	width.count(left, shl)
	width.count(right, shr)

	idx := GP64()
	XORQ(idx, idx)

	// Bottom-tested, so each iteration pays one taken branch rather than two.
	// n is a whole number of blocks, so the test before the loop is for zero.
	TESTQ(n, n)
	JEQ(LabelRef("done"))

	Label("loop")

	head, tail := width.vector(), width.vector()
	width.load(Mem{Base: src, Index: idx, Scale: 1}, head)
	width.load(Mem{Base: src, Index: idx, Scale: 1, Disp: 1}, tail)
	width.shl(shl, head)
	width.and(hi, head)
	width.shr(shr, tail)
	width.and(lo, tail)
	width.or(tail, head)
	width.store(head, Mem{Base: dst, Index: idx, Scale: 1})

	ADDQ(U32(width.lanes), idx)
	CMPQ(idx, n)
	JL(LabelRef("loop"))

	Label("done")
	width.epilogue()
	RET()
}

// _MaskHigh builds (0xFF << left) & 0xFF: the bits of a lane that survive the
// left shift, with the low bits that arrived from the neighbouring byte cleared.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
func _MaskHigh(left reg.Register) reg.Register {
	mask := GP32()

	MOVL(U32(BYTE_MASK), mask)
	MOVL(left, ECX)
	SHLL(CL, mask)
	ANDL(U32(BYTE_MASK), mask)

	return mask
}

// _MaskLow builds 0xFF >> right, the bits of a lane that survive the right shift.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
func _MaskLow(right reg.Register) reg.Register {
	mask := GP32()

	MOVL(U32(BYTE_MASK), mask)
	MOVL(right, ECX)
	SHRL(CL, mask)

	return mask
}

// _SSE2 is the 16-byte width, legacy encodings throughout.
//
// SSE2 has no byte broadcast, so one is built: the byte is unpacked to a word,
// the word to a doubleword, and the doubleword shuffled into all four lanes.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
func _SSE2() *_Width {
	return &_Width{
		name:   "SSE2",
		lanes:  LANES_SSE2,
		vector: XMM,
		broadcast: func(src reg.Register, dst reg.VecVirtual) {
			MOVD(src, dst)
			PUNPCKLBW(dst, dst)
			PUNPCKLWL(dst, dst)
			PSHUFD(U8(BROADCAST_ALL), dst, dst)
		},
		count: func(src reg.Register, dst reg.VecVirtual) {
			MOVD(src, dst)
		},
		load: func(src Mem, dst reg.VecVirtual) {
			MOVOU(src, dst)
		},
		store: func(src reg.VecVirtual, dst Mem) {
			MOVOU(src, dst)
		},
		shl: func(count, value reg.VecVirtual) {
			PSLLW(count, value)
		},
		shr: func(count, value reg.VecVirtual) {
			PSRLW(count, value)
		},
		and: func(mask, value reg.VecVirtual) {
			PAND(mask, value)
		},
		or: func(src, dst reg.VecVirtual) {
			POR(src, dst)
		},
		epilogue: func() {
			// Empty: no VEX instruction ran, so there is no upper state to clear.
		},
	}
}

// _AVX2 is the 32-byte width, VEX encodings throughout.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
func _AVX2() *_Width {
	return &_Width{
		name:   "AVX2",
		lanes:  LANES_AVX2,
		vector: YMM,
		broadcast: func(src reg.Register, dst reg.VecVirtual) {
			tmp := XMM()

			VMOVD(src, tmp)
			VPBROADCASTB(tmp, dst)
		},
		count: func(src reg.Register, dst reg.VecVirtual) {
			VMOVD(src, dst)
		},
		load: func(src Mem, dst reg.VecVirtual) {
			VMOVDQU(src, dst)
		},
		store: func(src reg.VecVirtual, dst Mem) {
			VMOVDQU(src, dst)
		},
		shl: func(count, value reg.VecVirtual) {
			VPSLLW(count, value, value)
		},
		shr: func(count, value reg.VecVirtual) {
			VPSRLW(count, value, value)
		},
		and: func(mask, value reg.VecVirtual) {
			VPAND(mask, value, value)
		},
		or: func(src, dst reg.VecVirtual) {
			VPOR(src, dst, dst)
		},
		epilogue: func() {
			VZEROUPPER()
		},
	}
}

// _AVX512 is the 64-byte width, EVEX encodings throughout. It needs AVX512BW
// for the word shifts and the byte broadcast, not just AVX512F.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
func _AVX512() *_Width {
	return &_Width{
		name:   "AVX512",
		lanes:  LANES_AVX512,
		vector: ZMM,
		broadcast: func(src reg.Register, dst reg.VecVirtual) {
			tmp := XMM()

			VMOVD(src, tmp)
			VPBROADCASTB(tmp, dst)
		},
		count: func(src reg.Register, dst reg.VecVirtual) {
			VMOVD(src, dst)
		},
		load: func(src Mem, dst reg.VecVirtual) {
			VMOVDQU8(src, dst)
		},
		store: func(src reg.VecVirtual, dst Mem) {
			VMOVDQU8(src, dst)
		},
		shl: func(count, value reg.VecVirtual) {
			VPSLLW(count, value, value)
		},
		shr: func(count, value reg.VecVirtual) {
			VPSRLW(count, value, value)
		},
		and: func(mask, value reg.VecVirtual) {
			VPANDD(mask, value, value)
		},
		or: func(src, dst reg.VecVirtual) {
			VPORD(src, dst, dst)
		},
		epilogue: func() {
			VZEROUPPER()
		},
	}
}

// _Lanes renders a width's lane count for its documentation.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
//   - 2026-09-23 05:31: strconv rather than a hand-rolled digit table, which
//     was avoiding an import at the cost of being read
func _Lanes(width *_Width) string {
	return strconv.Itoa(width.lanes)
}
