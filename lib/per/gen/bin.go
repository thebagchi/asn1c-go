//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"

	"github.com/mmcloughlin/avo/attr"
	"github.com/mmcloughlin/avo/reg"
)

// The binary-text conversions of types.go: a bit per character, leading bit
// first. Neither is on the wire path; both are exported for applications.
const (
	BINARY_ENCODE_BLOCK = 8
	BINARY_DECODE_BLOCK = 64

	CHAR_ZERO = 0x30
	CHAR_ONE  = 0x31
	LOW_BIT   = 0x01

	// One bit per lane, leading bit first: 0x80, 0x40, ... 0x01.
	BIT_MASKS = 0x0102040810204080
	// VPSHUFB indices that replicate each of eight bytes into eight lanes,
	// bytes 0-3 in the first table and 4-7 in the second.
	REPLICATE_0 = 0x0000000000000000
	REPLICATE_1 = 0x0101010101010101
	REPLICATE_2 = 0x0202020202020202
	REPLICATE_3 = 0x0303030303030303
	REPLICATE_4 = 0x0404040404040404
	REPLICATE_5 = 0x0505050505050505
	REPLICATE_6 = 0x0606060606060606
	REPLICATE_7 = 0x0707070707070707
	// VPSHUFB indices that reverse each run of eight lanes.
	REVERSE_LOW  = 0x0001020304050607
	REVERSE_HIGH = 0x08090A0B0C0D0E0F
	// Where the second half of a block's output goes.
	HALF_BLOCK = 4
)

// _Marks are the broadcast constants the binary classifier uses.
type _Marks struct {
	one     reg.VecVirtual
	ones    reg.VecVirtual
	reverse reg.VecVirtual
}

// _Bits are what one register of binary characters yields: the mask of lanes
// holding '0' or '1', and the bits themselves, gathered into a dword.
type _Bits struct {
	valid reg.Register
	bits  reg.Register
}

// _BinaryEncodeAVX2 renders eight bytes as sixty-four '0' and '1' characters
// per iteration, leading bit first.
//
// The eight bytes are broadcast to every lane, shuffled so each byte occupies
// eight consecutive lanes, and masked so each of those lanes keeps a different
// bit. A lane then compares equal to its mask exactly when its bit is set, and
// subtracting that all-ones result from '0' yields '1'.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _BinaryEncodeAVX2() {
	TEXT("_BinaryEncodeAVX2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_BinaryEncodeAVX2 renders src as '0' and '1' characters into dst, leading",
		"bit first, eight bytes per iteration, and returns how many bytes it",
		"consumed: a multiple of eight.",
		"",
		"len(dst) must be at least 8*len(src).",
	)

	masks := GLOBL("binary_bit_masks", attr.RODATA|attr.NOPTR)
	DATA(0, U64(BIT_MASKS))

	lowTable := GLOBL("binary_replicate_low", attr.RODATA|attr.NOPTR)
	DATA(0, U64(REPLICATE_0))
	DATA(8, U64(REPLICATE_1))
	DATA(16, U64(REPLICATE_2))
	DATA(24, U64(REPLICATE_3))

	highTable := GLOBL("binary_replicate_high", attr.RODATA|attr.NOPTR)
	DATA(0, U64(REPLICATE_4))
	DATA(8, U64(REPLICATE_5))
	DATA(16, U64(REPLICATE_6))
	DATA(24, U64(REPLICATE_7))

	args := _Load(BINARY_ENCODE_BLOCK)

	var (
		bits  = YMM()
		low   = YMM()
		high  = YMM()
		zeros = _BroadcastAVX2(CHAR_ZERO)
		in    = GP64()
		out   = GP64()
	)

	VPBROADCASTQ(masks, bits)
	VMOVDQU(lowTable, low)
	VMOVDQU(highTable, high)
	XORQ(in, in)
	XORQ(out, out)
	_Enter(args.limit)

	bytes := YMM()
	VPBROADCASTQ(Mem{Base: args.src, Index: in, Scale: 1}, bytes)

	_SpreadAVX2(bytes, low, bits, zeros, Mem{Base: args.dst, Index: out, Scale: 1})
	_SpreadAVX2(bytes, high, bits, zeros, Mem{
		Base: args.dst, Index: out, Scale: 1, Disp: AVX2_LANES,
	})

	ADDQ(U32(BINARY_ENCODE_BLOCK*BYTE_BITS), out)
	_Next(in, BINARY_ENCODE_BLOCK, args.limit)

	Label("done")
	VZEROUPPER()
	Store(in, ReturnIndex(0))
	RET()
}

// _SpreadAVX2 turns four of the broadcast bytes into thirty-two characters and
// stores them.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _SpreadAVX2(bytes, table, bits, zeros reg.VecVirtual, at Mem) {
	spread, chars := YMM(), YMM()

	VPSHUFB(table, bytes, spread)
	VPAND(bits, spread, spread)
	VPCMPEQB(bits, spread, spread)
	VPSUBB(spread, zeros, chars)
	VMOVDQU(chars, at)
}

// _BinaryDecodeAVX2 parses sixty-four '0' and '1' characters into eight bytes
// per iteration, leading character first.
//
// VPMOVMSKB gathers one bit per lane, but it takes lane 0 into bit 0, and the
// leading character of each byte is its most significant bit. Reversing each
// run of eight lanes first puts the bits where they belong.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _BinaryDecodeAVX2() {
	TEXT("_BinaryDecodeAVX2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_BinaryDecodeAVX2 parses '0' and '1' characters from src into bytes in",
		"dst, leading character first, sixty-four characters per iteration, and",
		"returns how many characters it consumed: a multiple of sixty-four, short",
		"of len(src) when a block holds a character that is neither.",
		"",
		"len(dst) must be at least len(src)/8.",
	)

	reverse := GLOBL("binary_reverse", attr.RODATA|attr.NOPTR)
	DATA(0, U64(REVERSE_LOW))
	DATA(8, U64(REVERSE_HIGH))

	args := _Load(BINARY_DECODE_BLOCK)

	var (
		marks = &_Marks{
			one:     _BroadcastAVX2(LOW_BIT),
			ones:    _BroadcastAVX2(CHAR_ONE),
			reverse: YMM(),
		}
		in  = GP64()
		out = GP64()
	)

	VBROADCASTI128(reverse, marks.reverse)
	XORQ(in, in)
	XORQ(out, out)
	_Enter(args.limit)

	var (
		first  = _GatherAVX2(marks, Mem{Base: args.src, Index: in, Scale: 1})
		second = _GatherAVX2(marks, Mem{
			Base: args.src, Index: in, Scale: 1, Disp: AVX2_LANES,
		})
	)

	ANDL(second.valid, first.valid)
	NOTL(first.valid)
	TESTL(first.valid, first.valid)
	JNE(LabelRef("done"))

	MOVL(first.bits, Mem{Base: args.dst, Index: out, Scale: 1})
	MOVL(second.bits, Mem{Base: args.dst, Index: out, Scale: 1, Disp: HALF_BLOCK})

	ADDQ(U32(BINARY_DECODE_BLOCK/BYTE_BITS), out)
	_Next(in, BINARY_DECODE_BLOCK, args.limit)

	Label("done")
	VZEROUPPER()
	Store(in, ReturnIndex(0))
	RET()
}

// _GatherAVX2 loads one register of characters and returns the mask of lanes
// that hold '0' or '1', and the thirty-two bits they denote.
//
// A character is valid when setting its low bit gives '1', which is true of
// '0' and '1' and of nothing else.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _GatherAVX2(marks *_Marks, at Mem) *_Bits {
	text, lifted, valid, set := YMM(), YMM(), YMM(), YMM()

	VMOVDQU(at, text)
	VPOR(marks.one, text, lifted)
	VPCMPEQB(marks.ones, lifted, valid)
	VPCMPEQB(marks.ones, text, set)
	VPSHUFB(marks.reverse, set, set)

	found := &_Bits{valid: GP32(), bits: GP32()}

	VPMOVMSKB(valid, found.valid)
	VPMOVMSKB(set, found.bits)

	return found
}
