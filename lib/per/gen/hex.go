//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"

	"github.com/mmcloughlin/avo/attr"
	"github.com/mmcloughlin/avo/reg"
)

// The hexadecimal conversions of types.go: a nibble per character with a
// sixteen-entry table. Neither is on the wire path; both are exported for
// applications, and an application rendering or parsing a large value pays
// what these save.
const (
	HEX_ENCODE_BLOCK = 32
	HEX_DECODE_BLOCK = 64

	// The characters and thresholds the classifier tests against: a digit is
	// at most 9 above '0', and once the case bit is set a letter is at most 5
	// above 'a' and worth ten more than that distance.
	LOWERCASE_BIT = 0x20
	LETTER_A      = 0x61
	LAST_LETTER   = 5
	LETTER_VALUE  = 10

	// The VPSHUFB table for encoding: "0123456789abcdef".
	HEX_TABLE_LOW  = 0x3736353433323130
	HEX_TABLE_HIGH = 0x6665646362613938
)

// _Digits are the broadcast constants the hexadecimal classifier uses.
type _Digits struct {
	zero   reg.VecVirtual
	nine   reg.VecVirtual
	fold   reg.VecVirtual
	letter reg.VecVirtual
	five   reg.VecVirtual
	ten    reg.VecVirtual
}

// _HexEncodeAVX2 renders thirty-two bytes as sixty-four hexadecimal characters
// per iteration.
//
// It is the NumericString unpack with a different table and nothing to
// validate: every nibble is a hexadecimal digit.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _HexEncodeAVX2() {
	TEXT("_HexEncodeAVX2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_HexEncodeAVX2 renders src as lowercase hexadecimal into dst, thirty-two",
		"bytes per iteration, and returns how many bytes it consumed: a multiple",
		"of thirty-two.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	table := GLOBL("hex_table", attr.RODATA|attr.NOPTR)
	DATA(0, U64(HEX_TABLE_LOW))
	DATA(8, U64(HEX_TABLE_HIGH))

	args := _Load(HEX_ENCODE_BLOCK)

	var (
		nibble = _BroadcastDwordAVX2(NIBBLE_WORDS)
		lookup = YMM()
		in     = GP64()
		out    = GP64()
	)

	VBROADCASTI128(table, lookup)
	XORQ(in, in)
	XORQ(out, out)
	_Enter(args.limit)

	packed, upper := YMM(), XMM()
	VMOVDQU(Mem{Base: args.src, Index: in, Scale: 1}, packed)
	VEXTRACTI128(U8(UPPER_HALF), packed, upper)

	chars := YMM()
	VPSHUFB(_SplitAVX2(nibble, packed.AsX()), lookup, chars)
	VMOVDQU(chars, Mem{Base: args.dst, Index: out, Scale: 1})
	VPSHUFB(_SplitAVX2(nibble, upper), lookup, chars)
	VMOVDQU(chars, Mem{Base: args.dst, Index: out, Scale: 1, Disp: AVX2_LANES})

	ADDQ(U32(2*HEX_ENCODE_BLOCK), out)
	_Next(in, HEX_ENCODE_BLOCK, args.limit)

	Label("done")
	VZEROUPPER()
	Store(in, ReturnIndex(0))
	RET()
}

// _HexDecodeAVX2 parses sixty-four hexadecimal characters into thirty-two
// bytes per iteration, in either letter case.
//
// It is the NumericString pack with a different classifier.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _HexDecodeAVX2() {
	TEXT("_HexDecodeAVX2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_HexDecodeAVX2 parses hexadecimal characters from src into bytes in dst,",
		"sixty-four characters per iteration, and returns how many characters it",
		"consumed: a multiple of sixty-four, short of len(src) when a block holds",
		"a character that is not a hexadecimal digit.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	weights := GLOBL("hex_pair_weights", attr.RODATA|attr.NOPTR)
	DATA(0, U64(PAIR_WEIGHTS))

	args := _Load(HEX_DECODE_BLOCK)

	var (
		digits = &_Digits{
			zero:   _BroadcastAVX2(DIGIT_ZERO),
			nine:   _BroadcastAVX2(LAST_DIGIT),
			fold:   _BroadcastAVX2(LOWERCASE_BIT),
			letter: _BroadcastAVX2(LETTER_A),
			five:   _BroadcastAVX2(LAST_LETTER),
			ten:    _BroadcastAVX2(LETTER_VALUE),
		}
		pairs = YMM()
		idx   = GP64()
		out   = GP64()
	)

	VPBROADCASTQ(weights, pairs)
	XORQ(idx, idx)
	XORQ(out, out)
	_Enter(args.limit)

	var (
		first  = _HexLanesAVX2(digits, Mem{Base: args.src, Index: idx, Scale: 1})
		second = _HexLanesAVX2(digits, Mem{
			Base: args.src, Index: idx, Scale: 1, Disp: AVX2_LANES,
		})
	)

	_AllLanesAVX2(first.valid, second.valid)

	packed := _PackPairsAVX2(pairs, first.index, second.index)
	VMOVDQU(packed, Mem{Base: args.dst, Index: out, Scale: 1})

	ADDQ(U32(HEX_DECODE_BLOCK/2), out)
	_Next(idx, HEX_DECODE_BLOCK, args.limit)

	Label("done")
	VZEROUPPER()
	Store(idx, ReturnIndex(0))
	RET()
}

// _HexLanesAVX2 loads one register of characters and returns which lanes hold
// a hexadecimal digit and the value of each.
//
// Setting the case bit folds 'A'..'F' onto 'a'..'f' and leaves the digits
// where they are, so two range tests cover all three ranges.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _HexLanesAVX2(digits *_Digits, at Mem) *_Lanes {
	text := YMM()
	VMOVDQU(at, text)

	// digit = text - '0'; it is one when min(digit, 9) == digit.
	digit, lower, isDigit := YMM(), YMM(), YMM()
	VPSUBB(digits.zero, text, digit)
	VPMINUB(digits.nine, digit, lower)
	VPCMPEQB(lower, digit, isDigit)

	// letter = (text | 0x20) - 'a'; it is one when min(letter, 5) == letter.
	folded, letter, bounded, isLetter := YMM(), YMM(), YMM(), YMM()
	VPOR(digits.fold, text, folded)
	VPSUBB(digits.letter, folded, letter)
	VPMINUB(digits.five, letter, bounded)
	VPCMPEQB(bounded, letter, isLetter)

	valid := YMM()
	VPOR(isLetter, isDigit, valid)

	// index = letter ? letter + 10 : digit.
	value, index := YMM(), YMM()
	VPADDB(digits.ten, letter, value)
	VPBLENDVB(isLetter, value, digit, index)

	return &_Lanes{valid: valid, index: index}
}
