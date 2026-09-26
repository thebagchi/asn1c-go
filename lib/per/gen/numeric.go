//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"

	"github.com/mmcloughlin/avo/attr"
	"github.com/mmcloughlin/avo/reg"
)

// NumericString is the one known-multiplier type whose alphabet fits a nibble:
// " 0123456789" is eleven characters, renumbered 0..10 by X.691 clause 30.4.4,
// four bits each in both PER variants. So two characters are exactly one byte,
// and a run of characters is a byte string - which the bit buffer already knows
// how to place at any bit offset. These kernels only do the part the buffer
// cannot: the per-character lookup, the validation, and the nibble packing.
const (
	SPACE        = 0x20
	LAST_INDEX   = 10
	INDEX_TO_CHR = DIGIT_ZERO - 1

	SSE2_CHARS = 16
	SSE2_BYTES = 8
	// The AVX2 kernels handle two registers per iteration, so that the
	// packing's permute and store, and the unpacking's load, run once per
	// sixty-four characters rather than once per thirty-two.
	AVX2_CHARS = 64
	AVX2_BYTES = 32

	// The VPSHUFB table for decoding: index 0 is a space and 1..10 the digits.
	TABLE_LOW  = 0x3635343332313020
	TABLE_HIGH = 0x0000000000393837
)

// _Letters are the broadcast constants the packing classifies characters
// against.
type _Letters struct {
	space reg.VecVirtual
	zero  reg.VecVirtual
	nine  reg.VecVirtual
	one   reg.VecVirtual
}

// _PackSSE2 packs sixteen characters into eight bytes per iteration.
//
// SSE2 has neither a byte-pair multiply-add nor a byte broadcast, so the pair
// is packed with word shifts - the even character's index shifted up by four
// in the low byte of its word, the odd one shifted down into the same byte -
// and the constants are broadcast as dwords.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: loop tests at the bottom
func _PackSSE2() {
	TEXT("_PackNumericSSE2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_PackNumericSSE2 packs pairs of NumericString characters from src into",
		"nibbles in dst, sixteen characters per iteration, and returns how many",
		"characters it consumed: a multiple of sixteen, short of len(src) when a",
		"block holds a character outside the alphabet.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	args := _Load(SSE2_CHARS)

	var (
		space = _BroadcastSSE2(SPACE * FOUR_BYTES)
		zero  = _BroadcastSSE2(DIGIT_ZERO * FOUR_BYTES)
		nine  = _BroadcastSSE2(LAST_DIGIT * FOUR_BYTES)
		one   = _BroadcastSSE2(FOUR_BYTES)
		bytes = _BroadcastSSE2(LOW_BYTE_WORDS)
		idx   = GP64()
		out   = GP64()
	)

	XORQ(idx, idx)
	XORQ(out, out)
	_Enter(args.limit)

	text := XMM()
	MOVOU(Mem{Base: args.src, Index: idx, Scale: 1}, text)

	// digit = text - '0'; a character is a digit when min(digit, 9) == digit.
	digit, lower := XMM(), XMM()
	MOVOU(text, digit)
	PSUBB(zero, digit)
	MOVOU(digit, lower)
	PMINUB(nine, lower)
	PCMPEQB(digit, lower)

	// space = (text == ' '); valid = space | digit.
	blank, valid := XMM(), XMM()
	MOVOU(text, blank)
	PCMPEQB(space, blank)
	MOVOU(lower, valid)
	POR(blank, valid)
	_AllLanesSSE2(valid)

	// index = space ? 0 : digit + 1, computed as (digit + 1) &^ space.
	PADDB(one, digit)
	PANDN(digit, blank)

	// Pair up: word = even<<4 | odd in the low byte, then drop the high bytes.
	high, low := XMM(), XMM()
	MOVOU(blank, high)
	PSLLW(U8(NIBBLE_BITS), high)
	MOVOU(blank, low)
	PSRLW(U8(BYTE_BITS), low)
	POR(low, high)
	PAND(bytes, high)
	PACKUSWB(high, high)
	MOVQ(high, Mem{Base: args.dst, Index: out, Scale: 1})

	ADDQ(U32(SSE2_BYTES), out)
	_Next(idx, SSE2_CHARS, args.limit)

	Label("done")
	Store(idx, ReturnIndex(0))
	RET()
}

// _PackAVX2 packs sixty-four characters into thirty-two bytes per iteration,
// two registers at a time.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: two registers per iteration, so the pack's permute
//     and store run half as often; loop tests at the bottom
func _PackAVX2() {
	TEXT("_PackNumericAVX2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_PackNumericAVX2 packs pairs of NumericString characters from src into",
		"nibbles in dst, sixty-four characters per iteration, and returns how many",
		"characters it consumed: a multiple of sixty-four, short of len(src) when",
		"a block holds a character outside the alphabet.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	weights := GLOBL("numeric_pair_weights", attr.RODATA|attr.NOPTR)
	DATA(0, U64(PAIR_WEIGHTS))

	args := _Load(AVX2_CHARS)

	var (
		letters = &_Letters{
			space: _BroadcastAVX2(SPACE),
			zero:  _BroadcastAVX2(DIGIT_ZERO),
			nine:  _BroadcastAVX2(LAST_DIGIT),
			one:   _BroadcastAVX2(1),
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
		first  = _ClassifyAVX2(letters, Mem{Base: args.src, Index: idx, Scale: 1})
		second = _ClassifyAVX2(letters, Mem{
			Base: args.src, Index: idx, Scale: 1, Disp: AVX2_LANES,
		})
	)

	_AllLanesAVX2(first.valid, second.valid)

	packed := _PackPairsAVX2(pairs, first.index, second.index)
	VMOVDQU(packed, Mem{Base: args.dst, Index: out, Scale: 1})

	ADDQ(U32(AVX2_BYTES), out)
	_Next(idx, AVX2_CHARS, args.limit)

	Label("done")
	VZEROUPPER()
	Store(idx, ReturnIndex(0))
	RET()
}

// _ClassifyAVX2 loads one register of characters and returns which lanes are
// in the alphabet and the index each maps to.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation, split out of _PackAVX2
func _ClassifyAVX2(letters *_Letters, at Mem) *_Lanes {
	text := YMM()
	VMOVDQU(at, text)

	// digit = text - '0'; a character is a digit when min(digit, 9) == digit.
	digit, lower, isDigit := YMM(), YMM(), YMM()
	VPSUBB(letters.zero, text, digit)
	VPMINUB(letters.nine, digit, lower)
	VPCMPEQB(lower, digit, isDigit)

	blank, valid := YMM(), YMM()
	VPCMPEQB(letters.space, text, blank)
	VPOR(blank, isDigit, valid)

	// index = space ? 0 : digit + 1, computed as (digit + 1) &^ space.
	index := YMM()
	VPADDB(letters.one, digit, index)
	VPANDN(index, blank, index)

	return &_Lanes{valid: valid, index: index}
}

// _UnpackSSE2 unpacks eight bytes into sixteen characters per iteration.
//
// Without a byte shuffle the character is computed rather than looked up:
// index + ('0' - 1) is right for every digit, and the one index that is a
// space is patched in with a mask.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: loop tests at the bottom
func _UnpackSSE2() {
	TEXT("_UnpackNumericSSE2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_UnpackNumericSSE2 unpacks nibbles from src into NumericString characters",
		"in dst, eight bytes per iteration, and returns how many bytes it consumed:",
		"a multiple of eight, short of len(src) when a block holds a nibble outside",
		"the alphabet.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	args := _Load(SSE2_BYTES)

	var (
		nibble = _BroadcastSSE2(NIBBLE_WORDS)
		ten    = _BroadcastSSE2(LAST_INDEX * FOUR_BYTES)
		offset = _BroadcastSSE2(INDEX_TO_CHR * FOUR_BYTES)
		space  = _BroadcastSSE2(SPACE * FOUR_BYTES)
		zero   = XMM()
		in     = GP64()
		out    = GP64()
	)

	PXOR(zero, zero)
	XORQ(in, in)
	XORQ(out, out)
	_Enter(args.limit)

	// Zero-extend eight bytes to words, then split each into its two nibbles
	// placed as the word's two bytes: high nibble first, as it was encoded.
	words, high := XMM(), XMM()
	MOVQ(Mem{Base: args.src, Index: in, Scale: 1}, words)
	PUNPCKLBW(zero, words)
	MOVOU(words, high)
	PSRLW(U8(NIBBLE_BITS), high)
	PAND(nibble, words)
	PSLLW(U8(BYTE_BITS), words)
	POR(words, high)

	// An index above ten is outside the alphabet: saturating subtraction of
	// ten leaves zero exactly for the valid ones.
	valid := XMM()
	MOVOU(high, valid)
	PSUBUSB(ten, valid)
	PCMPEQB(zero, valid)
	_AllLanesSSE2(valid)

	// chars = index + ('0' - 1), except where index == 0, which is a space.
	chars, blank, fill := XMM(), XMM(), XMM()
	MOVOU(high, chars)
	PADDB(offset, chars)
	MOVOU(high, blank)
	PCMPEQB(zero, blank)
	MOVOU(blank, fill)
	PAND(space, fill)
	PANDN(chars, blank)
	POR(fill, blank)
	MOVOU(blank, Mem{Base: args.dst, Index: out, Scale: 1})

	ADDQ(U32(SSE2_CHARS), out)
	_Next(in, SSE2_BYTES, args.limit)

	Label("done")
	Store(in, ReturnIndex(0))
	RET()
}

// _UnpackAVX2 unpacks thirty-two bytes into sixty-four characters per
// iteration, one register loaded and split into two.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: one thirty-two byte load per iteration, split in two,
//     so the load runs half as often; loop tests at the bottom
func _UnpackAVX2() {
	TEXT("_UnpackNumericAVX2", NOSPLIT, "func(dst, src []byte) int")
	Pragma("noescape")
	Doc(
		"_UnpackNumericAVX2 unpacks nibbles from src into NumericString characters",
		"in dst, thirty-two bytes per iteration, and returns how many bytes it",
		"consumed: a multiple of thirty-two, short of len(src) when a block holds",
		"a nibble outside the alphabet.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	table := GLOBL("numeric_table", attr.RODATA|attr.NOPTR)
	DATA(0, U64(TABLE_LOW))
	DATA(8, U64(TABLE_HIGH))

	args := _Load(AVX2_BYTES)

	var (
		nibble = _BroadcastDwordAVX2(NIBBLE_WORDS)
		ten    = _BroadcastAVX2(LAST_INDEX)
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

	var (
		first  = _SplitAVX2(nibble, packed.AsX())
		second = _SplitAVX2(nibble, upper)
	)

	_AllLanesAVX2(_ValidAVX2(ten, first), _ValidAVX2(ten, second))

	chars := YMM()
	VPSHUFB(first, lookup, chars)
	VMOVDQU(chars, Mem{Base: args.dst, Index: out, Scale: 1})
	VPSHUFB(second, lookup, chars)
	VMOVDQU(chars, Mem{Base: args.dst, Index: out, Scale: 1, Disp: AVX2_LANES})

	ADDQ(U32(AVX2_CHARS), out)
	_Next(in, AVX2_BYTES, args.limit)

	Label("done")
	VZEROUPPER()
	Store(in, ReturnIndex(0))
	RET()
}

// _ValidAVX2 marks the lanes whose index is in the alphabet: at most ten.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _ValidAVX2(ten reg.VecVirtual, index reg.VecVirtual) reg.VecVirtual {
	lower, valid := YMM(), YMM()

	VPMINUB(ten, index, lower)
	VPCMPEQB(lower, index, valid)

	return valid
}
