package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
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
// against, and the constant that pairs them: the weights the AVX2 packing
// multiplies with, or the mask the SSE2 packing drops high bytes with.
type _Letters struct {
	space reg.VecVirtual
	zero  reg.VecVirtual
	nine  reg.VecVirtual
	one   reg.VecVirtual
	pairs reg.VecVirtual
}

// _Spaces are what finding the blanks of one register of characters yields:
// which lanes are a space, and which are a space or a digit.
type _Spaces struct {
	blank reg.VecVirtual
	valid reg.VecVirtual
}

// _Indexes are the registers the SSE2 unpacking computes characters with.
type _Indexes struct {
	nibble reg.VecVirtual
	ten    reg.VecVirtual
	offset reg.VecVirtual
	space  reg.VecVirtual
	zero   reg.VecVirtual
}

// _Alphabet are the registers the AVX2 unpacking splits and looks up with.
type _Alphabet struct {
	nibble reg.VecVirtual
	ten    reg.VecVirtual
	lookup reg.VecVirtual
}

// _Nibbles are the two registers of nibble values that one unpack iteration
// splits its bytes into.
type _Nibbles struct {
	first  reg.VecVirtual
	second reg.VecVirtual
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
//   - 2026-10-20 13:58: split the classifying and the pairing into helpers to
//     stay under funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the block into _PackBlockSSE2; the generated
//     assembly is unchanged
func _PackSSE2() {
	_Begin(
		"_PackNumericSSE2",
		"_PackNumericSSE2 packs pairs of NumericString characters from src into",
		"nibbles in dst, sixteen characters per iteration, and returns how many",
		"characters it consumed: a multiple of sixteen, short of len(src) when a",
		"block holds a character outside the alphabet.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	var (
		args = _Load(SSE2_CHARS)

		letters = _LettersSSE2()
	)

	var (
		idx = GP64()
		out = GP64()
	)

	_Clear(
		idx,
		out,
	)
	_Enter(args.limit)
	_PackBlockSSE2(
		letters,
		args,
		idx,
		out,
	)

	ADDQ(
		U32(SSE2_BYTES),
		out,
	)
	_Next(
		idx,
		SSE2_CHARS,
		args.limit,
	)

	_Return(idx)
}

// _LettersSSE2 broadcasts the constants the SSE2 packing classifies against,
// and the mask that drops the high bytes of the paired words.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _PackSSE2
func _LettersSSE2() *_Letters {
	return &_Letters{
		space: _BroadcastSSE2(SPACE * FOUR_BYTES),
		zero:  _BroadcastSSE2(DIGIT_ZERO * FOUR_BYTES),
		nine:  _BroadcastSSE2(LAST_DIGIT * FOUR_BYTES),
		one:   _BroadcastSSE2(FOUR_BYTES),
		pairs: _BroadcastSSE2(LOW_BYTE_WORDS),
	}
}

// _PackBlockSSE2 classifies sixteen characters, leaves the loop when one is
// outside the alphabet, and stores the eight bytes they pack into.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _PackSSE2
func _PackBlockSSE2(
	letters *_Letters,
	args *_Args,
	idx,
	out reg.Register,
) {
	index := _ClassifySSE2(
		letters,
		Mem{
			Base:  args.src,
			Index: idx,
			Scale: 1,
		},
	)

	MOVQ(
		_PairSSE2(
			index,
			letters.pairs,
		),
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
}

// _ClassifySSE2 loads sixteen characters, leaves the loop when one is outside
// the alphabet, and returns the index each maps to.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _PackSSE2
func _ClassifySSE2(
	letters *_Letters,
	at Mem,
) reg.VecVirtual {
	text := XMM()
	MOVOU(
		at,
		text,
	)

	var (
		digit = _DigitTestSSE2(
			letters,
			text,
		)
		spaces = _SpacesSSE2(
			letters,
			text,
			digit,
		)
	)
	_AllLanesSSE2(spaces.valid)

	// index = space ? 0 : digit + 1, computed as (digit + 1) &^ space.
	PADDB(
		letters.one,
		digit.value,
	)
	PANDN(
		digit.value,
		spaces.blank,
	)

	return spaces.blank
}

// _DigitTestSSE2 subtracts '0' from each character and finds the digits.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _PackSSE2
func _DigitTestSSE2(
	letters *_Letters,
	text reg.VecVirtual,
) *_Probe {
	digit, lower := XMM(), XMM()

	// digit = text - '0'; a character is a digit when min(digit, 9) == digit.
	MOVOU(
		text,
		digit,
	)
	PSUBB(
		letters.zero,
		digit,
	)
	MOVOU(
		digit,
		lower,
	)
	PMINUB(
		letters.nine,
		lower,
	)
	PCMPEQB(
		digit,
		lower,
	)

	return &_Probe{
		value: digit,
		match: lower,
	}
}

// _SpacesSSE2 finds the spaces, and the characters that are a space or a
// digit, which are the ones in the alphabet.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _PackSSE2
func _SpacesSSE2(
	letters *_Letters,
	text reg.VecVirtual,
	digit *_Probe,
) *_Spaces {
	blank, valid := XMM(), XMM()

	// space = (text == ' '); valid = space | digit.
	MOVOU(
		text,
		blank,
	)
	PCMPEQB(
		letters.space,
		blank,
	)
	MOVOU(
		digit.match,
		valid,
	)
	POR(
		blank,
		valid,
	)

	return &_Spaces{
		blank: blank,
		valid: valid,
	}
}

// _PairSSE2 joins the indexes of each two adjacent characters into one byte.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _PackSSE2
func _PairSSE2(
	index,
	bytes reg.VecVirtual,
) reg.VecVirtual {
	high, low := XMM(), XMM()

	// Pair up: word = even<<4 | odd in the low byte, then drop the high bytes.
	MOVOU(
		index,
		high,
	)
	PSLLW(
		U8(NIBBLE_BITS),
		high,
	)
	MOVOU(
		index,
		low,
	)
	PSRLW(
		U8(BYTE_BITS),
		low,
	)
	POR(
		low,
		high,
	)
	PAND(
		bytes,
		high,
	)
	PACKUSWB(
		high,
		high,
	)

	return high
}

// _PackAVX2 packs sixty-four characters into thirty-two bytes per iteration,
// two registers at a time.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: two registers per iteration, so the pack's permute
//     and store run half as often; loop tests at the bottom
//   - 2026-10-20 13:58: split the block into _PackBlockAVX2 to stay under
//     funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the constants into _LettersAVX2; the generated
//     assembly is unchanged
func _PackAVX2() {
	_Begin(
		"_PackNumericAVX2",
		"_PackNumericAVX2 packs pairs of NumericString characters from src into",
		"nibbles in dst, sixty-four characters per iteration, and returns how many",
		"characters it consumed: a multiple of sixty-four, short of len(src) when",
		"a block holds a character outside the alphabet.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	var (
		weights = _Table(
			"numeric_pair_weights",
			PAIR_WEIGHTS,
		)

		args = _Load(AVX2_CHARS)
	)

	var (
		letters = _LettersAVX2(weights)
		idx     = GP64()
		out     = GP64()
	)

	_Clear(
		idx,
		out,
	)
	_Enter(args.limit)
	_PackBlockAVX2(
		letters,
		args,
		idx,
		out,
	)

	ADDQ(
		U32(AVX2_BYTES),
		out,
	)
	_Next(
		idx,
		AVX2_CHARS,
		args.limit,
	)

	_ReturnAVX2(idx)
}

// _LettersAVX2 broadcasts the constants the AVX2 packing classifies against,
// and the pair weights.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _PackAVX2
func _LettersAVX2(weights Mem) *_Letters {
	letters := &_Letters{
		space: _BroadcastAVX2(SPACE),
		zero:  _BroadcastAVX2(DIGIT_ZERO),
		nine:  _BroadcastAVX2(LAST_DIGIT),
		one:   _BroadcastAVX2(1),
		pairs: YMM(),
	}

	VPBROADCASTQ(
		weights,
		letters.pairs,
	)

	return letters
}

// _PackBlockAVX2 classifies sixty-four characters, leaves the loop when one is
// outside the alphabet, and stores the thirty-two bytes they pack into.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _PackAVX2
func _PackBlockAVX2(
	letters *_Letters,
	args *_Args,
	idx,
	out reg.Register,
) {
	var (
		first = _ClassifyAVX2(
			letters,
			Mem{
				Base:  args.src,
				Index: idx,
				Scale: 1,
			},
		)
		second = _ClassifyAVX2(
			letters,
			Mem{
				Base:  args.src,
				Index: idx,
				Scale: 1,
				Disp:  AVX2_LANES,
			},
		)
	)

	_AllLanesAVX2(
		first.valid,
		second.valid,
	)

	packed := _PackPairsAVX2(
		letters.pairs,
		first.index,
		second.index,
	)
	VMOVDQU(
		packed,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
}

// _ClassifyAVX2 loads one register of characters and returns which lanes are
// in the alphabet and the index each maps to.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation, split out of _PackAVX2
//   - 2026-10-20 13:58: split the digit test into _DigitTestAVX2 to stay under
//     funlen; the generated assembly is unchanged
func _ClassifyAVX2(
	letters *_Letters,
	at Mem,
) *_Lanes {
	text := YMM()
	VMOVDQU(
		at,
		text,
	)

	var (
		digit = _DigitTestAVX2(
			letters.zero,
			letters.nine,
			text,
		)

		blank, valid = YMM(), YMM()
	)
	VPCMPEQB(
		letters.space,
		text,
		blank,
	)
	VPOR(
		blank,
		digit.match,
		valid,
	)

	// index = space ? 0 : digit + 1, computed as (digit + 1) &^ space.
	index := YMM()
	VPADDB(
		letters.one,
		digit.value,
		index,
	)
	VPANDN(
		index,
		blank,
		index,
	)

	return &_Lanes{
		valid: valid,
		index: index,
	}
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
//   - 2026-10-20 13:58: split the split, the check and the characters into
//     helpers to stay under funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the constants and the block into _IndexesSSE2
//     and _UnpackBlockSSE2; the generated assembly is unchanged
func _UnpackSSE2() {
	_Begin(
		"_UnpackNumericSSE2",
		"_UnpackNumericSSE2 unpacks nibbles from src into NumericString characters",
		"in dst, eight bytes per iteration, and returns how many bytes it consumed:",
		"a multiple of eight, short of len(src) when a block holds a nibble outside",
		"the alphabet.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	args := _Load(SSE2_BYTES)

	var (
		indexes = _IndexesSSE2()
		in      = GP64()
		out     = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_UnpackBlockSSE2(
		indexes,
		args,
		in,
		out,
	)

	ADDQ(
		U32(SSE2_CHARS),
		out,
	)
	_Next(
		in,
		SSE2_BYTES,
		args.limit,
	)

	_Return(in)
}

// _IndexesSSE2 broadcasts the constants the SSE2 unpacking computes with, and
// clears the register of zeros.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _UnpackSSE2
func _IndexesSSE2() *_Indexes {
	indexes := &_Indexes{
		nibble: _BroadcastSSE2(NIBBLE_WORDS),
		ten:    _BroadcastSSE2(LAST_INDEX * FOUR_BYTES),
		offset: _BroadcastSSE2(INDEX_TO_CHR * FOUR_BYTES),
		space:  _BroadcastSSE2(SPACE * FOUR_BYTES),
		zero:   XMM(),
	}

	PXOR(
		indexes.zero,
		indexes.zero,
	)

	return indexes
}

// _UnpackBlockSSE2 loads eight bytes, leaves the loop when a nibble is outside
// the alphabet, and stores the sixteen characters they denote.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _UnpackSSE2
func _UnpackBlockSSE2(
	indexes *_Indexes,
	args *_Args,
	in,
	out reg.Register,
) {
	high := _SplitSSE2(
		indexes,
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
	)
	_AllLanesSSE2(
		_ValidSSE2(
			indexes,
			high,
		),
	)
	MOVOU(
		_CharsSSE2(
			indexes,
			high,
		),
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
}

// _SplitSSE2 zero-extends eight bytes to words, then splits each into its two
// nibbles placed as the word's two bytes: high nibble first, as it was encoded.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _UnpackSSE2
func _SplitSSE2(
	indexes *_Indexes,
	at Mem,
) reg.VecVirtual {
	words, high := XMM(), XMM()

	MOVQ(
		at,
		words,
	)
	PUNPCKLBW(
		indexes.zero,
		words,
	)
	MOVOU(
		words,
		high,
	)
	PSRLW(
		U8(NIBBLE_BITS),
		high,
	)
	PAND(
		indexes.nibble,
		words,
	)
	PSLLW(
		U8(BYTE_BITS),
		words,
	)
	POR(
		words,
		high,
	)

	return high
}

// _ValidSSE2 marks the lanes whose index is in the alphabet.
//
// An index above ten is outside it: saturating subtraction of ten leaves zero
// exactly for the valid ones.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _UnpackSSE2
func _ValidSSE2(
	indexes *_Indexes,
	high reg.VecVirtual,
) reg.VecVirtual {
	valid := XMM()

	MOVOU(
		high,
		valid,
	)
	PSUBUSB(
		indexes.ten,
		valid,
	)
	PCMPEQB(
		indexes.zero,
		valid,
	)

	return valid
}

// _CharsSSE2 computes the character of each index.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _UnpackSSE2
func _CharsSSE2(
	indexes *_Indexes,
	high reg.VecVirtual,
) reg.VecVirtual {
	chars, blank, fill := XMM(), XMM(), XMM()

	// chars = index + ('0' - 1), except where index == 0, which is a space.
	MOVOU(
		high,
		chars,
	)
	PADDB(
		indexes.offset,
		chars,
	)
	MOVOU(
		high,
		blank,
	)
	PCMPEQB(
		indexes.zero,
		blank,
	)
	MOVOU(
		blank,
		fill,
	)
	PAND(
		indexes.space,
		fill,
	)
	PANDN(
		chars,
		blank,
	)
	POR(
		fill,
		blank,
	)

	return blank
}

// _UnpackAVX2 unpacks thirty-two bytes into sixty-four characters per
// iteration, one register loaded and split into two.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: one thirty-two byte load per iteration, split in two,
//     so the load runs half as often; loop tests at the bottom
//   - 2026-10-20 13:58: split the block into _UnpackBlockAVX2 to stay under
//     funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the constants into _AlphabetAVX2; the generated
//     assembly is unchanged
//   - 2026-10-20 14:00: split the nibble split and the check into
//     _SplitHalvesAVX2 and _CheckNibblesAVX2; the generated assembly is
//     unchanged
func _UnpackAVX2() {
	_Begin(
		"_UnpackNumericAVX2",
		"_UnpackNumericAVX2 unpacks nibbles from src into NumericString characters",
		"in dst, thirty-two bytes per iteration, and returns how many bytes it",
		"consumed: a multiple of thirty-two, short of len(src) when a block holds",
		"a nibble outside the alphabet.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	var (
		table = _Table(
			"numeric_table",
			TABLE_LOW,
			TABLE_HIGH,
		)

		args = _Load(AVX2_BYTES)
	)

	var (
		alphabet = _AlphabetAVX2(table)
		in       = GP64()
		out      = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_UnpackBlockAVX2(
		alphabet,
		args,
		in,
		out,
	)

	ADDQ(
		U32(AVX2_CHARS),
		out,
	)
	_Next(
		in,
		AVX2_BYTES,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _AlphabetAVX2 broadcasts the constants the AVX2 unpacking splits and checks
// with, and the table it looks characters up in.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _UnpackAVX2
func _AlphabetAVX2(table Mem) *_Alphabet {
	alphabet := &_Alphabet{
		nibble: _BroadcastDwordAVX2(NIBBLE_WORDS),
		ten:    _BroadcastAVX2(LAST_INDEX),
		lookup: YMM(),
	}

	VBROADCASTI128(
		table,
		alphabet.lookup,
	)

	return alphabet
}

// _UnpackBlockAVX2 loads thirty-two bytes, leaves the loop when a nibble is
// outside the alphabet, and stores the sixty-four characters they denote.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _UnpackAVX2
func _UnpackBlockAVX2(
	alphabet *_Alphabet,
	args *_Args,
	in,
	out reg.Register,
) {
	var (
		source = _LoadHalvesAVX2(
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
			},
		)

		nibbles = _SplitHalvesAVX2(
			alphabet,
			source,
		)
	)

	_CheckNibblesAVX2(
		alphabet,
		nibbles,
	)

	chars := YMM()
	_StoreCharsAVX2(
		alphabet.lookup,
		nibbles.first,
		chars,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	_StoreCharsAVX2(
		alphabet.lookup,
		nibbles.second,
		chars,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  AVX2_LANES,
		},
	)
}

// _CheckNibblesAVX2 leaves the loop unless every nibble of both registers is
// in the alphabet.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _UnpackBlockAVX2
func _CheckNibblesAVX2(
	alphabet *_Alphabet,
	nibbles *_Nibbles,
) {
	_AllLanesAVX2(
		_ValidAVX2(
			alphabet.ten,
			nibbles.first,
		),
		_ValidAVX2(
			alphabet.ten,
			nibbles.second,
		),
	)
}

// _SplitHalvesAVX2 splits both halves of the loaded bytes into nibbles.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _UnpackBlockAVX2
func _SplitHalvesAVX2(
	alphabet *_Alphabet,
	source *_Source,
) *_Nibbles {
	return &_Nibbles{
		first: _SplitAVX2(
			alphabet.nibble,
			source.packed.AsX(),
		),
		second: _SplitAVX2(
			alphabet.nibble,
			source.upper,
		),
	}
}

// _ValidAVX2 marks the lanes whose index is in the alphabet: at most ten.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _ValidAVX2(
	ten reg.VecVirtual,
	index reg.VecVirtual,
) reg.VecVirtual {
	lower, valid := YMM(), YMM()

	VPMINUB(
		ten,
		index,
		lower,
	)
	VPCMPEQB(
		lower,
		index,
		valid,
	)

	return valid
}

// _NumericLanes512 is what classifying one ZMM register of characters yields:
// the mask of lanes in the alphabet, and the index each lane maps to.
type _NumericLanes512 struct {
	valid reg.OpmaskVirtual
	index reg.VecVirtual
}

// _NumericHalves512 are the two registers of nibble values that one AVX-512
// unpack iteration splits its sixty-four bytes into.
type _NumericHalves512 struct {
	first  reg.VecVirtual
	second reg.VecVirtual
}

// The AVX-512 kernels handle twice the AVX2 block, so each register of an
// iteration is a full ZMM of sixty-four lanes.
const (
	NUMERIC_AVX512_CHARS = 128
	NUMERIC_AVX512_BYTES = 64

	// The VPERMQ index that puts the qwords of the packed pairs back in order:
	// the in-lane pack leaves them as first, second, first, second and so on.
	ORDER_QWORDS_0 = 0
	ORDER_QWORDS_1 = 2
	ORDER_QWORDS_2 = 4
	ORDER_QWORDS_3 = 6
	ORDER_QWORDS_4 = 1
	ORDER_QWORDS_5 = 3
	ORDER_QWORDS_6 = 5
	ORDER_QWORDS_7 = 7
)

// _PackAVX512 packs one hundred and twenty-eight characters into sixty-four
// bytes per iteration, two ZMM registers at a time, in EVEX encodings only.
//
// Compares write mask registers, so there is no VPMOVMSKB: the two validity
// masks are ANDed and KORTESTQ leaves the loop unless all of them are set.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
//   - 2026-10-22 00:01: split the constants into _NumericPackerAVX512 to stay under funlen
func _PackAVX512() {
	_Begin(
		"_PackNumericAVX512",
		"_PackNumericAVX512 packs pairs of NumericString characters from src into",
		"nibbles in dst, one hundred and twenty-eight characters per iteration, in",
		"EVEX encodings only, and returns how many characters it consumed: a multiple",
		"of one hundred and twenty-eight, short of len(src) when a block holds a",
		"character outside the alphabet.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	var (
		args = _Load(NUMERIC_AVX512_CHARS)

		packer = _NumericPackerAVX512()
		idx    = GP64()
		out    = GP64()
	)

	_Clear(
		idx,
		out,
	)
	_Enter(args.limit)
	_NumericPackBlockAVX512(
		packer,
		args,
		idx,
		out,
	)

	ADDQ(
		U32(NUMERIC_AVX512_BYTES),
		out,
	)
	_Next(
		idx,
		NUMERIC_AVX512_CHARS,
		args.limit,
	)

	_ReturnAVX2(idx)
}

// _NumericPacker are the constants of the AVX-512 packing: the ones it classifies
// against, and the VPERMQ index that puts the packed qwords in order.
type _NumericPacker struct {
	letters *_Letters
	sorted  reg.VecVirtual
}

// _NumericPackerAVX512 broadcasts the constants the AVX-512 packing classifies
// against, and loads the pair weights and the qword order.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _PackAVX512 (review P33)
func _NumericPackerAVX512() *_NumericPacker {
	var (
		weights = _Table(
			"numeric_pair_weights_avx512",
			PAIR_WEIGHTS,
		)
		order = _Table(
			"numeric_order_qwords",
			ORDER_QWORDS_0,
			ORDER_QWORDS_1,
			ORDER_QWORDS_2,
			ORDER_QWORDS_3,
			ORDER_QWORDS_4,
			ORDER_QWORDS_5,
			ORDER_QWORDS_6,
			ORDER_QWORDS_7,
		)

		packer = &_NumericPacker{
			letters: _NumericLettersAVX512(weights),
			sorted:  ZMM(),
		}
	)

	VMOVDQU64(
		order,
		packer.sorted,
	)

	return packer
}

// _NumericLettersAVX512 broadcasts the constants the AVX-512 packing classifies
// against, and the pair weights.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _NumericLettersAVX512(weights Mem) *_Letters {
	letters := &_Letters{
		space: _BroadcastAVX512(SPACE),
		zero:  _BroadcastAVX512(DIGIT_ZERO),
		nine:  _BroadcastAVX512(LAST_DIGIT),
		one:   _BroadcastAVX512(1),
		pairs: ZMM(),
	}

	VPBROADCASTQ(
		weights,
		letters.pairs,
	)

	return letters
}

// _NumericPackBlockAVX512 classifies one hundred and twenty-eight characters,
// leaves the loop when one is outside the alphabet, and stores the sixty-four
// bytes they pack into.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
//   - 2026-10-22 00:01: takes the constants as one _NumericPacker, for the argument limit
func _NumericPackBlockAVX512(
	packer *_NumericPacker,
	args *_Args,
	idx,
	out reg.Register,
) {
	var (
		first = _NumericClassifyAVX512(
			packer.letters,
			Mem{
				Base:  args.src,
				Index: idx,
				Scale: 1,
			},
		)
		second = _NumericClassifyAVX512(
			packer.letters,
			Mem{
				Base:  args.src,
				Index: idx,
				Scale: 1,
				Disp:  AVX512_LANES,
			},
		)

		both = K()
	)

	KANDQ(
		first.valid,
		second.valid,
		both,
	)
	_AllLanesAVX512(both)

	VMOVDQU8(
		_NumericPairsAVX512(
			packer.letters.pairs,
			packer.sorted,
			first.index,
			second.index,
		),
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
}

// _NumericDigits512 is what testing one ZMM register of characters against the
// digits yields: each character less '0', and the mask of lanes that are a digit.
type _NumericDigits512 struct {
	value reg.VecVirtual
	match reg.OpmaskVirtual
}

// _NumericClassifyAVX512 loads one ZMM register of characters and returns the
// mask of lanes in the alphabet and the index each maps to.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
//   - 2026-10-22 00:01: split the digit test into _NumericDigitTestAVX512 to stay under funlen
func _NumericClassifyAVX512(
	letters *_Letters,
	at Mem,
) *_NumericLanes512 {
	var (
		text               = ZMM()
		blank, valid, keep = K(), K(), K()
		index              = ZMM()
	)

	VMOVDQU8(
		at,
		text,
	)

	digit := _NumericDigitTestAVX512(
		letters,
		text,
	)
	VPCMPEQB(
		letters.space,
		text,
		blank,
	)
	KORQ(
		blank,
		digit.match,
		valid,
	)

	// index = space ? 0 : digit + 1: the zeroing mask is every lane but a space.
	KNOTQ(
		blank,
		keep,
	)
	VPADDB_Z(
		letters.one,
		digit.value,
		keep,
		index,
	)

	return &_NumericLanes512{
		valid: valid,
		index: index,
	}
}

// _NumericDigitTestAVX512 subtracts '0' from each lane and finds the lanes that
// are a digit.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _NumericClassifyAVX512 (review P33)
func _NumericDigitTestAVX512(
	letters *_Letters,
	text reg.VecVirtual,
) *_NumericDigits512 {
	var (
		digit, lower = ZMM(), ZMM()
		match        = K()
	)

	// digit = text - '0'; a character is a digit when min(digit, 9) == digit.
	VPSUBB(
		letters.zero,
		text,
		digit,
	)
	VPMINUB(
		letters.nine,
		digit,
		lower,
	)
	VPCMPEQB(
		lower,
		digit,
		match,
	)

	return &_NumericDigits512{
		value: digit,
		match: match,
	}
}

// _NumericPairsAVX512 packs two registers of indexes, one hundred and
// twenty-eight in all, into sixty-four bytes in order.
//
// Each pair of adjacent indexes becomes first*16 + second in one word. The
// in-lane pack interleaves the qwords of the two registers, and VPERMQ with an
// index vector puts them back in order across lanes.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _NumericPairsAVX512(
	pairs,
	sorted,
	first,
	second reg.VecVirtual,
) reg.VecVirtual {
	low, high := ZMM(), ZMM()

	VPMADDUBSW(
		pairs,
		first,
		low,
	)
	VPMADDUBSW(
		pairs,
		second,
		high,
	)
	VPACKUSWB(
		high,
		low,
		low,
	)
	VPERMQ(
		low,
		sorted,
		low,
	)

	return low
}

// _UnpackAVX512 unpacks sixty-four bytes into one hundred and twenty-eight
// characters per iteration, one ZMM load split into two, in EVEX encodings only.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _UnpackAVX512() {
	_Begin(
		"_UnpackNumericAVX512",
		"_UnpackNumericAVX512 unpacks nibbles from src into NumericString characters",
		"in dst, sixty-four bytes per iteration, in EVEX encodings only, and returns",
		"how many bytes it consumed: a multiple of sixty-four, short of len(src) when",
		"a block holds a nibble outside the alphabet.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	var (
		table = _Table(
			"numeric_table_avx512",
			TABLE_LOW,
			TABLE_HIGH,
		)

		args = _Load(NUMERIC_AVX512_BYTES)
	)

	var (
		alphabet = _NumericAlphabetAVX512(table)
		in       = GP64()
		out      = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_NumericUnpackBlockAVX512(
		alphabet,
		args,
		in,
		out,
	)

	ADDQ(
		U32(NUMERIC_AVX512_CHARS),
		out,
	)
	_Next(
		in,
		NUMERIC_AVX512_BYTES,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _NumericAlphabetAVX512 broadcasts the constants the AVX-512 unpacking splits
// and checks with, and the table it looks characters up in.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _NumericAlphabetAVX512(table Mem) *_Alphabet {
	var (
		scalar   = GP32()
		alphabet = &_Alphabet{
			ten:    _BroadcastAVX512(LAST_INDEX),
			nibble: ZMM(),
			lookup: ZMM(),
		}
	)

	MOVL(
		U32(NIBBLE_WORDS),
		scalar,
	)
	VPBROADCASTD(
		scalar,
		alphabet.nibble,
	)
	VBROADCASTI32X4(
		table,
		alphabet.lookup,
	)

	return alphabet
}

// _NumericUnpackBlockAVX512 loads sixty-four bytes, leaves the loop when a
// nibble is outside the alphabet, and stores the one hundred and twenty-eight
// characters they denote.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
//   - 2026-10-22 00:01: split the load and the check into helpers to stay under funlen
func _NumericUnpackBlockAVX512(
	alphabet *_Alphabet,
	args *_Args,
	in,
	out reg.Register,
) {
	nibbles := _NumericHalvesAVX512(
		alphabet,
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
	)

	_NumericCheckAVX512(
		alphabet,
		nibbles,
	)

	chars := ZMM()
	_NumericStoreAVX512(
		alphabet.lookup,
		nibbles.first,
		chars,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	_NumericStoreAVX512(
		alphabet.lookup,
		nibbles.second,
		chars,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  AVX512_LANES,
		},
	)
}

// _NumericHalvesAVX512 loads sixty-four bytes and splits both halves into
// nibbles.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _NumericUnpackBlockAVX512 (review P33)
func _NumericHalvesAVX512(
	alphabet *_Alphabet,
	at Mem,
) *_NumericHalves512 {
	var (
		packed = ZMM()
		upper  = YMM()
	)

	VMOVDQU8(
		at,
		packed,
	)
	VEXTRACTI64X4(
		U8(UPPER_HALF),
		packed,
		upper,
	)

	return &_NumericHalves512{
		first: _NumericSplitAVX512(
			alphabet.nibble,
			packed.AsY(),
		),
		second: _NumericSplitAVX512(
			alphabet.nibble,
			upper,
		),
	}
}

// _NumericCheckAVX512 leaves the loop unless every nibble of both registers is
// in the alphabet.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _NumericUnpackBlockAVX512 (review P33)
func _NumericCheckAVX512(
	alphabet *_Alphabet,
	nibbles *_NumericHalves512,
) {
	var (
		first, second = K(), K()
		both          = K()
	)

	_NumericValidAVX512(
		alphabet.ten,
		nibbles.first,
		first,
	)
	_NumericValidAVX512(
		alphabet.ten,
		nibbles.second,
		second,
	)
	KANDQ(
		first,
		second,
		both,
	)
	_AllLanesAVX512(both)
}

// _NumericSplitAVX512 zero-extends thirty-two packed bytes to words and places
// each byte's two nibbles as the word's two bytes, high nibble first.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _NumericSplitAVX512(
	nibble reg.VecVirtual,
	packed reg.Register,
) reg.VecVirtual {
	words, high, low, index := ZMM(), ZMM(), ZMM(), ZMM()

	VPMOVZXBW(
		packed,
		words,
	)
	VPSRLW(
		U8(NIBBLE_BITS),
		words,
		high,
	)
	VPANDD(
		nibble,
		words,
		low,
	)
	VPSLLW(
		U8(BYTE_BITS),
		low,
		low,
	)
	VPORD(
		low,
		high,
		index,
	)

	return index
}

// _NumericValidAVX512 sets the mask of lanes whose index is at most ten.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
//   - 2026-10-22 00:01: takes the mask as a parameter, for ireturn
func _NumericValidAVX512(
	ten,
	index reg.VecVirtual,
	valid reg.OpmaskVirtual,
) {
	lower := ZMM()

	VPMINUB(
		ten,
		index,
		lower,
	)
	VPCMPEQB(
		lower,
		index,
		valid,
	)
}

// _NumericStoreAVX512 looks each index up in the table and stores the sixty-four
// characters. The caller owns the character register, so that the two stores
// of an iteration reuse one.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _NumericStoreAVX512(
	lookup,
	index,
	chars reg.VecVirtual,
	at Mem,
) {
	VPSHUFB(
		index,
		lookup,
		chars,
	)
	VMOVDQU8(
		chars,
		at,
	)
}
