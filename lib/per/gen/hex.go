package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

// The hexadecimal conversions of types.go: a nibble per character with a
// sixteen-entry table. Neither is on the wire path; both are exported for
// applications, and an application rendering or parsing a large value pays
// what these save.
const (
	HEX_ENCODE_BLOCK = 32
	HEX_DECODE_BLOCK = 64

	// Two characters for each octet: the output of an encode block, and of a decode block.
	HEX_ENCODED_BLOCK = 2 * HEX_ENCODE_BLOCK
	HEX_DECODED_BLOCK = HEX_DECODE_BLOCK / 2

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

	// The AVX-512 blocks are twice the AVX2 blocks.
	HEX_ENCODE_BLOCK_AVX512  = 2 * HEX_ENCODE_BLOCK
	HEX_DECODE_BLOCK_AVX512  = 2 * HEX_DECODE_BLOCK
	HEX_ENCODED_BLOCK_AVX512 = 2 * HEX_ENCODE_BLOCK_AVX512
	HEX_DECODED_BLOCK_AVX512 = HEX_DECODE_BLOCK_AVX512 / 2

	// The nibble mask, and the VPCMPUB predicate "less than or equal".
	HEX_NIBBLE_BYTE = 0x0F
	COMPARE_LE      = 2
)

// HEX_ORDER are the VPERMT2Q indexes, one qword each, that put the in-lane
// unpacks back in order: bit 3 selects the second source. The first eight build
// the low half of the characters, the last eight the high half.
var (
	HEX_ORDER = []uint64{
		0, 1, 8, 9, 2, 3, 10, 11,
		4, 5, 12, 13, 6, 7, 14, 15,
	}
)

// _Digits are the broadcast constants the hexadecimal classifier uses, and the
// pair weights the decoder packs with.
type _Digits struct {
	zero   reg.VecVirtual
	nine   reg.VecVirtual
	fold   reg.VecVirtual
	letter reg.VecVirtual
	five   reg.VecVirtual
	ten    reg.VecVirtual
	pairs  reg.VecVirtual
}

// _Render are the registers the hexadecimal encoder looks nibbles up with.
type _Render struct {
	nibble reg.VecVirtual
	lookup reg.VecVirtual
}

// _HexEncodeAVX2 renders thirty-two bytes as sixty-four hexadecimal characters
// per iteration.
//
// It is the NumericString unpack with a different table and nothing to
// validate: every nibble is a hexadecimal digit.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
//   - 2026-10-20 13:58: split the block into _EncodeBlockAVX2 to stay under
//     funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the constants into _RenderAVX2; the generated
//     assembly is unchanged
func _HexEncodeAVX2() {
	_Begin(
		"_HexEncodeAVX2",
		"_HexEncodeAVX2 renders src as lowercase hexadecimal into dst, thirty-two",
		"bytes per iteration, and returns how many bytes it consumed: a multiple",
		"of thirty-two.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	var (
		table = _Table(
			"hex_table",
			HEX_TABLE_LOW,
			HEX_TABLE_HIGH,
		)

		args = _Load(HEX_ENCODE_BLOCK)
	)

	var (
		render = _RenderAVX2(table)
		in     = GP64()
		out    = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_EncodeBlockAVX2(
		render,
		args,
		in,
		out,
	)

	ADDQ(
		U32(HEX_ENCODED_BLOCK),
		out,
	)
	_Next(
		in,
		HEX_ENCODE_BLOCK,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _RenderAVX2 broadcasts the nibble mask and the digit table the hexadecimal
// encoder looks up with.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _HexEncodeAVX2
func _RenderAVX2(table Mem) *_Render {
	render := &_Render{
		nibble: _BroadcastDwordAVX2(NIBBLE_WORDS),
		lookup: YMM(),
	}

	VBROADCASTI128(
		table,
		render.lookup,
	)

	return render
}

// _EncodeBlockAVX2 loads thirty-two bytes and stores their sixty-four
// hexadecimal characters, one half of the bytes at a time.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _HexEncodeAVX2
func _EncodeBlockAVX2(
	render *_Render,
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

		chars = YMM()
	)
	_StoreCharsAVX2(
		render.lookup,
		_SplitAVX2(
			render.nibble,
			source.packed.AsX(),
		),
		chars,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	_StoreCharsAVX2(
		render.lookup,
		_SplitAVX2(
			render.nibble,
			source.upper,
		),
		chars,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  AVX2_LANES,
		},
	)
}

// _HexDecodeAVX2 parses sixty-four hexadecimal characters into thirty-two
// bytes per iteration, in either letter case.
//
// It is the NumericString pack with a different classifier.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
//   - 2026-10-20 13:58: split the block into _DecodeBlockAVX2 to stay under
//     funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the constants into _DigitsAVX2; the generated
//     assembly is unchanged
func _HexDecodeAVX2() {
	_Begin(
		"_HexDecodeAVX2",
		"_HexDecodeAVX2 parses hexadecimal characters from src into bytes in dst,",
		"sixty-four characters per iteration, and returns how many characters it",
		"consumed: a multiple of sixty-four, short of len(src) when a block holds",
		"a character that is not a hexadecimal digit.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	var (
		weights = _Table(
			"hex_pair_weights",
			PAIR_WEIGHTS,
		)

		args = _Load(HEX_DECODE_BLOCK)
	)

	var (
		digits = _DigitsAVX2(weights)
		idx    = GP64()
		out    = GP64()
	)

	_Clear(
		idx,
		out,
	)
	_Enter(args.limit)
	_DecodeBlockAVX2(
		digits,
		args,
		idx,
		out,
	)

	ADDQ(
		U32(HEX_DECODED_BLOCK),
		out,
	)
	_Next(
		idx,
		HEX_DECODE_BLOCK,
		args.limit,
	)

	_ReturnAVX2(idx)
}

// _DigitsAVX2 broadcasts the constants the hexadecimal classifier tests
// against, and the pair weights.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _HexDecodeAVX2
func _DigitsAVX2(weights Mem) *_Digits {
	digits := &_Digits{
		zero:   _BroadcastAVX2(DIGIT_ZERO),
		nine:   _BroadcastAVX2(LAST_DIGIT),
		fold:   _BroadcastAVX2(LOWERCASE_BIT),
		letter: _BroadcastAVX2(LETTER_A),
		five:   _BroadcastAVX2(LAST_LETTER),
		ten:    _BroadcastAVX2(LETTER_VALUE),
		pairs:  YMM(),
	}

	VPBROADCASTQ(
		weights,
		digits.pairs,
	)

	return digits
}

// _DecodeBlockAVX2 classifies sixty-four characters, leaves the loop when one
// is not a hexadecimal digit, and stores the thirty-two bytes they denote.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _HexDecodeAVX2
func _DecodeBlockAVX2(
	digits *_Digits,
	args *_Args,
	idx,
	out reg.Register,
) {
	var (
		first = _HexLanesAVX2(
			digits,
			Mem{
				Base:  args.src,
				Index: idx,
				Scale: 1,
			},
		)
		second = _HexLanesAVX2(
			digits,
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
		digits.pairs,
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

// _HexLanesAVX2 loads one register of characters and returns which lanes hold
// a hexadecimal digit and the value of each.
//
// Setting the case bit folds 'A'..'F' onto 'a'..'f' and leaves the digits
// where they are, so two range tests cover all three ranges.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
//   - 2026-10-20 13:58: split the two range tests into _DigitTestAVX2 and
//     _LetterTestAVX2 to stay under funlen; the generated assembly is
//     unchanged
func _HexLanesAVX2(
	digits *_Digits,
	at Mem,
) *_Lanes {
	text := YMM()
	VMOVDQU(
		at,
		text,
	)

	var (
		digit = _DigitTestAVX2(
			digits.zero,
			digits.nine,
			text,
		)
		letter = _LetterTestAVX2(
			digits,
			text,
		)

		valid = YMM()
	)
	VPOR(
		letter.match,
		digit.match,
		valid,
	)

	// index = letter ? letter + 10 : digit.
	value, index := YMM(), YMM()
	VPADDB(
		digits.ten,
		letter.value,
		value,
	)
	VPBLENDVB(
		letter.match,
		value,
		digit.value,
		index,
	)

	return &_Lanes{
		valid: valid,
		index: index,
	}
}

// _LetterTestAVX2 folds the case of each lane, subtracts 'a', and finds the
// lanes that are a letter from 'a' to 'f'.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _HexLanesAVX2
func _LetterTestAVX2(
	digits *_Digits,
	text reg.VecVirtual,
) *_Probe {
	folded, letter, bounded, isLetter := YMM(), YMM(), YMM(), YMM()

	// letter = (text | 0x20) - 'a'; it is one when min(letter, 5) == letter.
	VPOR(
		digits.fold,
		text,
		folded,
	)
	VPSUBB(
		digits.letter,
		folded,
		letter,
	)
	VPMINUB(
		digits.five,
		letter,
		bounded,
	)
	VPCMPEQB(
		bounded,
		letter,
		isLetter,
	)

	return &_Probe{
		value: letter,
		match: isLetter,
	}
}

// _Wide are the registers the AVX-512 hexadecimal encoder works with.
type _Wide struct {
	nibble reg.VecVirtual
	lookup reg.VecVirtual
	order  Mem
}

// _HexEncodeAVX512 renders sixty-four bytes as one hundred and twenty-eight
// hexadecimal characters per iteration: twice the AVX2 block, in EVEX encodings
// only.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation, empty until its kernel is written (review P33)
//   - 2026-10-21 23:57: the kernel (review P33)
func _HexEncodeAVX512() {
	_Begin(
		"_HexEncodeAVX512",
		"_HexEncodeAVX512 renders src as lowercase hexadecimal into dst, sixty-four",
		"bytes per iteration, and returns how many bytes it consumed: a multiple",
		"of sixty-four.",
		"",
		"len(dst) must be at least 2*len(src).",
	)

	var (
		args = _Load(HEX_ENCODE_BLOCK_AVX512)
		wide = _WideAVX512()
		in   = GP64()
		out  = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_EncodeBlockAVX512(
		wide,
		args,
		in,
		out,
	)

	ADDQ(
		U32(HEX_ENCODED_BLOCK_AVX512),
		out,
	)
	_Next(
		in,
		HEX_ENCODE_BLOCK_AVX512,
		args.limit,
	)

	_ReturnAVX512(in)
}

// _WideAVX512 emits the encoder's tables and loads the registers it looks
// nibbles up with.
//
// Revisions:
//   - 2026-10-22 00:00: initial creation, split out of _HexEncodeAVX512 to stay
//     under funlen (review P33)
func _WideAVX512() *_Wide {
	var (
		table = _Table(
			"hex_table_avx512",
			HEX_TABLE_LOW,
			HEX_TABLE_HIGH,
		)
		order = _Table(
			"hex_order_avx512",
			HEX_ORDER...,
		)

		wide = &_Wide{
			nibble: _BroadcastAVX512(HEX_NIBBLE_BYTE),
			lookup: ZMM(),
			order:  order,
		}
	)

	VBROADCASTI32X4(
		table,
		wide.lookup,
	)

	return wide
}

// _EncodeBlockAVX512 loads sixty-four bytes and stores their hundred and
// twenty-eight characters.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _EncodeBlockAVX512(
	wide *_Wide,
	args *_Args,
	in,
	out reg.Register,
) {
	source := ZMM()
	VMOVDQU8(
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		source,
	)

	low, high := _HexUnpackAVX512(
		wide,
		source,
	)

	for half, chars := range []reg.VecVirtual{low, high} {
		VMOVDQU8(
			chars,
			Mem{
				Base:  args.dst,
				Index: out,
				Scale: 1,
				Disp:  half * AVX512_LANES,
			},
		)
	}
}

// _HexUnpackAVX512 turns sixty-four bytes into two registers of characters.
//
// A nibble is looked up in the table, the high nibbles and the low nibbles
// separately. The in-lane unpacks interleave them, but leave the sixteen-byte
// lanes in the order (a0, a1, a2, a3) and (b0, b1, b2, b3); one two-source
// permute for each half of the output restores the order a0 b0 a1 b1 ...
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _HexUnpackAVX512(
	wide *_Wide,
	source reg.VecVirtual,
) (reg.VecVirtual, reg.VecVirtual) {
	high, low := ZMM(), ZMM()

	VPSRLW(
		U8(NIBBLE_BITS),
		source,
		high,
	)
	VPANDQ(
		wide.nibble,
		high,
		high,
	)
	VPANDQ(
		wide.nibble,
		source,
		low,
	)
	first, second := _InterleaveAVX512(
		wide.lookup,
		high,
		low,
	)

	return _OrderAVX512(
		wide.order,
		first,
		second,
	)
}

// _InterleaveAVX512 looks the high and the low nibbles up and interleaves the
// characters in each lane: the low eight bytes of every lane into first, the
// high eight into second.
//
// Revisions:
//   - 2026-10-22 00:00: initial creation, split out of _HexUnpackAVX512 to stay
//     under funlen (review P33)
func _InterleaveAVX512(
	lookup,
	high,
	low reg.VecVirtual,
) (reg.VecVirtual, reg.VecVirtual) {
	var (
		highChars, lowChars = ZMM(), ZMM()
		first, second       = ZMM(), ZMM()
	)

	VPSHUFB(
		high,
		lookup,
		highChars,
	)
	VPSHUFB(
		low,
		lookup,
		lowChars,
	)
	VPUNPCKLBW(
		lowChars,
		highChars,
		first,
	)
	VPUNPCKHBW(
		lowChars,
		highChars,
		second,
	)

	return first, second
}

// _OrderAVX512 restores the order a0 b0 a1 b1 ... of the sixteen-byte lanes
// with one two-source permute for each half of the output, and returns the low
// half and the high half.
//
// Revisions:
//   - 2026-10-22 00:00: initial creation, split out of _HexUnpackAVX512 to stay
//     under funlen (review P33)
func _OrderAVX512(
	order Mem,
	first,
	second reg.VecVirtual,
) (reg.VecVirtual, reg.VecVirtual) {
	index, copied := ZMM(), ZMM()

	VMOVDQU64(
		order,
		index,
	)
	VMOVDQA64(
		first,
		copied,
	)
	VPERMT2Q(
		second,
		index,
		copied,
	)
	VMOVDQU64(
		order.Offset(AVX512_LANES),
		index,
	)
	VPERMT2Q(
		second,
		index,
		first,
	)

	return copied, first
}

// _HexDecodeAVX512 parses one hundred and twenty-eight hexadecimal characters
// into sixty-four bytes per iteration, in either letter case: twice the AVX2
// block, in EVEX encodings only.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation, empty until its kernel is written (review P33)
//   - 2026-10-21 23:57: the kernel (review P33)
func _HexDecodeAVX512() {
	_Begin(
		"_HexDecodeAVX512",
		"_HexDecodeAVX512 parses hexadecimal characters from src into bytes in dst,",
		"one hundred and twenty-eight characters per iteration, and returns how many",
		"characters it consumed: a multiple of one hundred and twenty-eight, short of",
		"len(src) when a block holds a character that is not a hexadecimal digit.",
		"",
		"len(dst) must be at least len(src)/2.",
	)

	var (
		weights = _Table(
			"hex_pair_weights_avx512",
			PAIR_WEIGHTS,
		)

		args = _Load(HEX_DECODE_BLOCK_AVX512)
	)

	var (
		digits = _DigitsAVX512(weights)
		idx    = GP64()
		out    = GP64()
	)

	_Clear(
		idx,
		out,
	)
	_Enter(args.limit)
	_DecodeBlockAVX512(
		digits,
		args,
		idx,
		out,
	)

	ADDQ(
		U32(HEX_DECODED_BLOCK_AVX512),
		out,
	)
	_Next(
		idx,
		HEX_DECODE_BLOCK_AVX512,
		args.limit,
	)

	_ReturnAVX512(idx)
}

// _DigitsAVX512 broadcasts the constants the hexadecimal classifier tests
// against, and the pair weights.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _DigitsAVX512(weights Mem) *_Digits {
	digits := &_Digits{
		zero:   _BroadcastAVX512(DIGIT_ZERO),
		nine:   _BroadcastAVX512(LAST_DIGIT),
		fold:   _BroadcastAVX512(LOWERCASE_BIT),
		letter: _BroadcastAVX512(LETTER_A),
		five:   _BroadcastAVX512(LAST_LETTER),
		ten:    _BroadcastAVX512(LETTER_VALUE),
		pairs:  ZMM(),
	}

	VPBROADCASTQ(
		weights,
		digits.pairs,
	)

	return digits
}

// _DecodeBlockAVX512 classifies one hundred and twenty-eight characters, leaves
// the loop when one is not a hexadecimal digit, and stores the sixty-four bytes
// they denote.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _DecodeBlockAVX512(
	digits *_Digits,
	args *_Args,
	idx,
	out reg.Register,
) {
	var (
		first = _HexLanesAVX512(
			digits,
			Mem{
				Base:  args.src,
				Index: idx,
				Scale: 1,
			},
		)
		second = _HexLanesAVX512(
			digits,
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

	for half, lanes := range []*_HexNibbles{first, second} {
		_StorePairsAVX512(
			digits.pairs,
			lanes.index,
			Mem{
				Base:  args.dst,
				Index: out,
				Scale: 1,
				Disp:  half * AVX2_LANES,
			},
		)
	}
}

// _StorePairsAVX512 joins each pair of adjacent nibble values into a byte
// (first*16 + second, in one word) and stores the thirty-two bytes. VPMOVWB
// keeps the low byte of each word, so the bytes stay in order.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _StorePairsAVX512(
	pairs,
	index reg.VecVirtual,
	at Mem,
) {
	words := ZMM()

	VPMADDUBSW(
		pairs,
		index,
		words,
	)
	VPMOVWB(
		words,
		at,
	)
}

// _HexLanesAVX512 loads sixty-four characters and returns which lanes hold a
// hexadecimal digit, as a mask, and the value of each.
//
// Setting the case bit folds 'A'..'F' onto 'a'..'f' and leaves the digits
// where they are, so two range tests cover all three ranges. A letter lane is
// then raised by ten under its mask, which leaves the digit lanes alone.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _HexLanesAVX512(
	digits *_Digits,
	at Mem,
) *_HexNibbles {
	var (
		text  = ZMM()
		valid = K()
	)

	VMOVDQU8(
		at,
		text,
	)

	var (
		digit = _HexDigitTestAVX512(
			digits,
			text,
		)
		letter = _HexLetterTestAVX512(
			digits,
			text,
		)
	)

	KORQ(
		letter.match,
		digit.match,
		valid,
	)

	// index = letter ? letter + 10 : digit.
	VPADDB(
		digits.ten,
		letter.value,
		letter.match,
		digit.value,
	)

	return &_HexNibbles{
		valid: valid,
		index: digit.value,
	}
}

// _HexProbe is the value of each lane after a range test, and the mask of the
// lanes that passed it.
type _HexProbe struct {
	value reg.VecVirtual
	match reg.OpmaskVirtual
}

// _HexDigitTestAVX512 subtracts '0' from each lane and finds the lanes that are
// a digit.
//
// Revisions:
//   - 2026-10-22 00:00: initial creation, split out of _HexLanesAVX512 to stay
//     under funlen (review P33)
func _HexDigitTestAVX512(
	digits *_Digits,
	text reg.VecVirtual,
) *_HexProbe {
	var (
		digit   = ZMM()
		isDigit = K()
	)

	// digit = text - '0'; it is a digit when digit <= 9.
	VPSUBB(
		digits.zero,
		text,
		digit,
	)
	VPCMPUB(
		U8(COMPARE_LE),
		digits.nine,
		digit,
		isDigit,
	)

	return &_HexProbe{
		value: digit,
		match: isDigit,
	}
}

// _HexLetterTestAVX512 folds the case of each lane, subtracts 'a', and finds
// the lanes that are a letter from 'a' to 'f'.
//
// Revisions:
//   - 2026-10-22 00:00: initial creation, split out of _HexLanesAVX512 to stay
//     under funlen (review P33)
func _HexLetterTestAVX512(
	digits *_Digits,
	text reg.VecVirtual,
) *_HexProbe {
	var (
		folded, letter = ZMM(), ZMM()
		isLetter       = K()
	)

	// letter = (text | 0x20) - 'a'; it is a letter when letter <= 5.
	VPORQ(
		digits.fold,
		text,
		folded,
	)
	VPSUBB(
		digits.letter,
		folded,
		letter,
	)
	VPCMPUB(
		U8(COMPARE_LE),
		digits.five,
		letter,
		isLetter,
	)

	return &_HexProbe{
		value: letter,
		match: isLetter,
	}
}

// _HexNibbles is a mask of the lanes that hold a hexadecimal digit and the value of each.
type _HexNibbles struct {
	valid reg.OpmaskVirtual
	index reg.VecVirtual
}

// _ReturnAVX512 closes an AVX-512 kernel: VZEROUPPER, then the done label's return.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _ReturnAVX512(consumed reg.Register) {
	_ReturnAVX2(consumed)
}
