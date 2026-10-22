package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
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

	// The SSE2 blocks: four bytes to thirty-two characters, and back.
	BINARY_ENCODE_SSE2 = 4
	BINARY_DECODE_SSE2 = 32
	// PSHUFLW and PSHUFHW immediate that reverses the four words of a half.
	REVERSE_WORDS = 0x1B
	// The bits of the second register of a decode block go above the first.
	SECOND_HALF_BITS = 16

	// The AVX-512 blocks: sixteen bytes to one hundred and twenty-eight characters, and back.
	BINARY_ENCODE_AVX512 = 16
	BINARY_DECODE_AVX512 = 128
	// Where the second register of an AVX-512 encode block reads its bytes, and where
	// the second octet group of a decode block goes.
	SECOND_OCTETS = 8
)

// _Planes are the registers one AVX-512 binary encode iteration spreads bytes with:
// the bit mask of each lane, the replicating shuffle, and '0'.
type _Planes struct {
	bits  reg.VecVirtual
	table reg.VecVirtual
	zeros reg.VecVirtual
}

// _Flags are what one ZMM register of binary characters yields: the mask of lanes
// holding '0' or '1', and the bits themselves, gathered into a qword.
type _Flags struct {
	valid reg.OpmaskVirtual
	bits  reg.Register
}

// _Pattern is what the SSE2 encoder spreads bytes into characters with: the bit
// mask of each lane, eight lanes to a byte, and '0' in every lane.
type _Pattern struct {
	bits  reg.VecVirtual
	zeros reg.VecVirtual
}

// _Halves are the two registers that the SSE2 encoder spreads four bytes over: bytes 0
// and 1 in low, bytes 2 and 3 in high, each in eight lanes.
type _Halves struct {
	low  reg.VecVirtual
	high reg.VecVirtual
}

// _Tests are the broadcast constants the SSE2 classifier tests against. SSE2 has
// no PSHUFB, so it reverses lanes with shuffles and needs no reverse table.
type _Tests struct {
	one  reg.VecVirtual
	ones reg.VecVirtual
}

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

// _BitPair are the two registers of characters that one decode iteration
// gathers.
type _BitPair struct {
	first  *_Bits
	second *_Bits
}

// _Spread are the registers the binary encoder spreads bytes into characters
// with: the bit mask of each lane, the two replicating shuffles, and '0'.
type _Spread struct {
	bits  reg.VecVirtual
	low   reg.VecVirtual
	high  reg.VecVirtual
	zeros reg.VecVirtual
}

// _Replicas are the addresses of the tables the binary encoder loads.
type _Replicas struct {
	masks Mem
	low   Mem
	high  Mem
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
//   - 2026-10-20 13:58: split the tables, the constants and the block into
//     helpers to stay under funlen; the generated assembly is unchanged
func _BinaryEncodeAVX2() {
	_Begin(
		"_BinaryEncodeAVX2",
		"_BinaryEncodeAVX2 renders src as '0' and '1' characters into dst, leading",
		"bit first, eight bytes per iteration, and returns how many bytes it",
		"consumed: a multiple of eight.",
		"",
		"len(dst) must be at least 8*len(src).",
	)

	var (
		replicas = _ReplicasAVX2()
		args     = _Load(BINARY_ENCODE_BLOCK)
		spread   = _SpreadConstantsAVX2(replicas)
	)

	var (
		in  = GP64()
		out = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_EncodeBitsAVX2(
		spread,
		args,
		in,
		out,
	)

	ADDQ(
		U32(BINARY_ENCODE_BLOCK*BYTE_BITS),
		out,
	)
	_Next(
		in,
		BINARY_ENCODE_BLOCK,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _ReplicasAVX2 emits the three tables of the binary encoder.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _BinaryEncodeAVX2
func _ReplicasAVX2() *_Replicas {
	var (
		masks = _Table(
			"binary_bit_masks",
			BIT_MASKS,
		)

		low = _Table(
			"binary_replicate_low",
			REPLICATE_0,
			REPLICATE_1,
			REPLICATE_2,
			REPLICATE_3,
		)

		high = _Table(
			"binary_replicate_high",
			REPLICATE_4,
			REPLICATE_5,
			REPLICATE_6,
			REPLICATE_7,
		)
	)

	return &_Replicas{
		masks: masks,
		low:   low,
		high:  high,
	}
}

// _SpreadConstantsAVX2 loads the registers the binary encoder spreads with.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _BinaryEncodeAVX2
func _SpreadConstantsAVX2(replicas *_Replicas) *_Spread {
	spread := &_Spread{
		bits:  YMM(),
		low:   YMM(),
		high:  YMM(),
		zeros: _BroadcastAVX2(CHAR_ZERO),
	}

	VPBROADCASTQ(
		replicas.masks,
		spread.bits,
	)
	VMOVDQU(
		replicas.low,
		spread.low,
	)
	VMOVDQU(
		replicas.high,
		spread.high,
	)

	return spread
}

// _EncodeBitsAVX2 broadcasts eight bytes and stores their sixty-four
// characters, thirty-two at a time.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _BinaryEncodeAVX2
func _EncodeBitsAVX2(
	spread *_Spread,
	args *_Args,
	in,
	out reg.Register,
) {
	bytes := YMM()
	VPBROADCASTQ(
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		bytes,
	)

	_SpreadAVX2(
		spread,
		bytes,
		spread.low,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	_SpreadAVX2(
		spread,
		bytes,
		spread.high,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  AVX2_LANES,
		},
	)
}

// _SpreadAVX2 turns four of the broadcast bytes into thirty-two characters and
// stores them.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
//   - 2026-10-20 13:58: the bit masks and '0' come in one struct to stay under
//     the argument limit; the generated assembly is unchanged
func _SpreadAVX2(
	spread *_Spread,
	bytes,
	table reg.VecVirtual,
	at Mem,
) {
	lanes, chars := YMM(), YMM()

	VPSHUFB(
		table,
		bytes,
		lanes,
	)
	VPAND(
		spread.bits,
		lanes,
		lanes,
	)
	VPCMPEQB(
		spread.bits,
		lanes,
		lanes,
	)
	VPSUBB(
		lanes,
		spread.zeros,
		chars,
	)
	VMOVDQU(
		chars,
		at,
	)
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
//   - 2026-10-20 13:58: split the constants and the block into helpers to stay
//     under funlen; the generated assembly is unchanged
//   - 2026-10-20 14:00: split the constants into _MarksAVX2; the generated
//     assembly is unchanged
func _BinaryDecodeAVX2() {
	_Begin(
		"_BinaryDecodeAVX2",
		"_BinaryDecodeAVX2 parses '0' and '1' characters from src into bytes in",
		"dst, leading character first, sixty-four characters per iteration, and",
		"returns how many characters it consumed: a multiple of sixty-four, short",
		"of len(src) when a block holds a character that is neither.",
		"",
		"len(dst) must be at least len(src)/8.",
	)

	var (
		reverse = _Table(
			"binary_reverse",
			REVERSE_LOW,
			REVERSE_HIGH,
		)

		args = _Load(BINARY_DECODE_BLOCK)
	)

	var (
		marks = _MarksAVX2(reverse)
		in    = GP64()
		out   = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_DecodeBitsAVX2(
		marks,
		args,
		in,
		out,
	)

	ADDQ(
		U32(BINARY_DECODE_BLOCK/BYTE_BITS),
		out,
	)
	_Next(
		in,
		BINARY_DECODE_BLOCK,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _MarksAVX2 broadcasts the constants the binary classifier tests against.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _BinaryDecodeAVX2
func _MarksAVX2(reverse Mem) *_Marks {
	marks := &_Marks{
		one:     _BroadcastAVX2(LOW_BIT),
		ones:    _BroadcastAVX2(CHAR_ONE),
		reverse: YMM(),
	}

	VBROADCASTI128(
		reverse,
		marks.reverse,
	)

	return marks
}

// _DecodeBitsAVX2 gathers sixty-four characters, leaves the loop when one is
// neither '0' nor '1', and stores the eight bytes they denote.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation, split out of _BinaryDecodeAVX2
func _DecodeBitsAVX2(
	marks *_Marks,
	args *_Args,
	in,
	out reg.Register,
) {
	pair := &_BitPair{
		first: _GatherAVX2(
			marks,
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
			},
		),
		second: _GatherAVX2(
			marks,
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
				Disp:  AVX2_LANES,
			},
		),
	}

	_LeaveInvalidAVX2(pair)

	MOVL(
		pair.first.bits,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	MOVL(
		pair.second.bits,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  HALF_BLOCK,
		},
	)
}

// _GatherAVX2 loads one register of characters and returns the mask of lanes
// that hold '0' or '1', and the thirty-two bits they denote.
//
// A character is valid when setting its low bit gives '1', which is true of
// '0' and '1' and of nothing else.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation
func _GatherAVX2(
	marks *_Marks,
	at Mem,
) *_Bits {
	text, lifted, valid, set := YMM(), YMM(), YMM(), YMM()

	VMOVDQU(
		at,
		text,
	)
	VPOR(
		marks.one,
		text,
		lifted,
	)
	VPCMPEQB(
		marks.ones,
		lifted,
		valid,
	)
	VPCMPEQB(
		marks.ones,
		text,
		set,
	)
	VPSHUFB(
		marks.reverse,
		set,
		set,
	)

	found := &_Bits{
		valid: GP32(),
		bits:  GP32(),
	}

	VPMOVMSKB(
		valid,
		found.valid,
	)
	VPMOVMSKB(
		set,
		found.bits,
	)

	return found
}

// _LeaveInvalidAVX2 leaves the loop unless every character of both registers
// is '0' or '1'.
//
// Revisions:
//   - 2026-10-20 14:00: initial creation, split out of _DecodeBitsAVX2
func _LeaveInvalidAVX2(pair *_BitPair) {
	ANDL(
		pair.second.valid,
		pair.first.valid,
	)
	NOTL(pair.first.valid)
	TESTL(
		pair.first.valid,
		pair.first.valid,
	)
	JNE(LabelRef("done"))
}

// _BinaryEncodeSSE2 renders four bytes as thirty-two '0' and '1' characters per
// iteration, leading bit first, with SSE2 only.
//
// SSE2 has no PSHUFB, so the unpacks double the four bytes three times until each
// byte fills eight lanes; the mask, the compare and the subtract from '0' are those
// of _BinaryEncodeAVX2.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _BinaryEncodeSSE2() {
	_Begin(
		"_BinaryEncodeSSE2",
		"_BinaryEncodeSSE2 renders src as '0' and '1' characters into dst, leading",
		"bit first, four bytes per iteration, and returns how many bytes it",
		"consumed: a multiple of four.",
		"",
		"len(dst) must be at least 8*len(src).",
	)

	var (
		args    = _Load(BINARY_ENCODE_SSE2)
		pattern = _PatternSSE2()
		in      = GP64()
		out     = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_EncodeBitsSSE2(
		pattern,
		args,
		in,
		out,
	)

	ADDQ(
		U32(BINARY_ENCODE_SSE2*BYTE_BITS),
		out,
	)
	_Next(
		in,
		BINARY_ENCODE_SSE2,
		args.limit,
	)

	_Return(in)
}

// _EncodeBitsSSE2 spreads four bytes over two registers, eight lanes to a byte,
// and stores their thirty-two characters.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _EncodeBitsSSE2(
	pattern *_Pattern,
	args *_Args,
	in,
	out reg.Register,
) {
	var (
		word   = GP32()
		packed = XMM()
	)

	MOVL(
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		word,
	)
	MOVD(
		word,
		packed,
	)

	halves := _DoubleSSE2(packed)

	_StoreBitsSSE2(
		pattern,
		halves.low,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	_StoreBitsSSE2(
		pattern,
		halves.high,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  SSE2_LANES,
		},
	)
}

// _StoreBitsSSE2 keeps one bit of each lane of a register of spread bytes, turns
// it into '0' or '1', and stores the sixteen characters.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _StoreBitsSSE2(
	pattern *_Pattern,
	lanes reg.VecVirtual,
	at Mem,
) {
	chars := XMM()

	// A lane equals its mask exactly when its bit is set; '0' minus all ones is '1'.
	PAND(
		pattern.bits,
		lanes,
	)
	PCMPEQB(
		pattern.bits,
		lanes,
	)
	MOVO(
		pattern.zeros,
		chars,
	)
	PSUBB(
		lanes,
		chars,
	)
	MOVOU(
		chars,
		at,
	)
}

// _BinaryDecodeSSE2 parses thirty-two '0' and '1' characters into four bytes per
// iteration, leading character first, with SSE2 only.
//
// The test is that of _BinaryDecodeAVX2. SSE2 has no PSHUFB, so each run of eight
// lanes is reversed by a byte swap inside each word and a reverse of the words,
// before PMOVMSKB takes lane 0 into bit 0.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _BinaryDecodeSSE2() {
	_Begin(
		"_BinaryDecodeSSE2",
		"_BinaryDecodeSSE2 parses '0' and '1' characters from src into bytes in",
		"dst, leading character first, thirty-two characters per iteration, and",
		"returns how many characters it consumed: a multiple of thirty-two, short",
		"of len(src) when a block holds a character that is neither.",
		"",
		"len(dst) must be at least len(src)/8.",
	)

	var (
		args  = _Load(BINARY_DECODE_SSE2)
		tests = &_Tests{
			one:  _BroadcastSSE2(LOW_BIT * FOUR_BYTES),
			ones: _BroadcastSSE2(CHAR_ONE * FOUR_BYTES),
		}
		in  = GP64()
		out = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_DecodeBitsSSE2(
		tests,
		args,
		in,
		out,
	)

	ADDQ(
		U32(BINARY_DECODE_SSE2/BYTE_BITS),
		out,
	)
	_Next(
		in,
		BINARY_DECODE_SSE2,
		args.limit,
	)

	_Return(in)
}

// _DecodeBitsSSE2 gathers thirty-two characters, leaves the loop when one is
// neither '0' nor '1', and stores the four bytes they denote.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _DecodeBitsSSE2(
	tests *_Tests,
	args *_Args,
	in,
	out reg.Register,
) {
	pair := &_BitPair{
		first: _GatherSSE2(
			tests,
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
			},
		),
		second: _GatherSSE2(
			tests,
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
				Disp:  SSE2_LANES,
			},
		),
	}

	_LeaveInvalidSSE2(pair)

	SHLL(
		U8(SECOND_HALF_BITS),
		pair.second.bits,
	)
	ORL(
		pair.second.bits,
		pair.first.bits,
	)
	MOVL(
		pair.first.bits,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
}

// _GatherSSE2 loads sixteen characters and returns the mask of lanes that hold
// '0' or '1', and the sixteen bits they denote, leading character first.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _GatherSSE2(
	tests *_Tests,
	at Mem,
) *_Bits {
	var (
		text  = XMM()
		valid = XMM()
		found = &_Bits{
			valid: GP32(),
			bits:  GP32(),
		}
	)

	MOVOU(
		at,
		text,
	)

	// A character is valid when setting its low bit gives '1'.
	MOVO(
		text,
		valid,
	)
	POR(
		tests.one,
		valid,
	)
	PCMPEQB(
		tests.ones,
		valid,
	)
	PCMPEQB(
		tests.ones,
		text,
	)
	_ReverseLanesSSE2(text)

	PMOVMSKB(
		valid,
		found.valid,
	)
	PMOVMSKB(
		text,
		found.bits,
	)

	return found
}

// _ReverseLanesSSE2 reverses each run of eight byte lanes: the bytes of each word
// swap, then the four words of each half reverse.
//
// Revisions:
//   - 2026-10-21 21:35: initial creation (review P31)
func _ReverseLanesSSE2(lanes reg.VecVirtual) {
	swap := XMM()

	MOVO(
		lanes,
		swap,
	)
	PSLLW(
		U8(BYTE_BITS),
		swap,
	)
	PSRLW(
		U8(BYTE_BITS),
		lanes,
	)
	POR(
		swap,
		lanes,
	)
	PSHUFLW(
		U8(REVERSE_WORDS),
		lanes,
		lanes,
	)
	PSHUFHW(
		U8(REVERSE_WORDS),
		lanes,
		lanes,
	)
}

// _PatternSSE2 emits the table of lane masks and loads the registers the SSE2 encoder
// spreads with.
//
// Revisions:
//   - 2026-10-21 21:58: initial creation, split out of _BinaryEncodeSSE2 (review P31)
func _PatternSSE2() *_Pattern {
	var (
		masks = _Table(
			"binary_bit_masks_sse2",
			BIT_MASKS,
			BIT_MASKS,
		)
		pattern = &_Pattern{
			bits:  XMM(),
			zeros: _BroadcastSSE2(CHAR_ZERO * FOUR_BYTES),
		}
	)

	MOVOU(
		masks,
		pattern.bits,
	)

	return pattern
}

// _DoubleSSE2 doubles the four bytes of packed three times, so that each byte fills
// eight lanes: bytes 0 and 1 in the low register, bytes 2 and 3 in the high one.
//
// Revisions:
//   - 2026-10-21 21:58: initial creation, split out of _EncodeBitsSSE2 (review P31)
func _DoubleSSE2(packed reg.VecVirtual) *_Halves {
	halves := &_Halves{
		low:  XMM(),
		high: XMM(),
	}

	// b0 b1 b2 b3 -> each byte twice -> four times -> eight times, in two halves.
	PUNPCKLBW(
		packed,
		packed,
	)
	PUNPCKLWL(
		packed,
		packed,
	)
	MOVO(
		packed,
		halves.low,
	)
	PUNPCKLLQ(
		halves.low,
		halves.low,
	)
	MOVO(
		packed,
		halves.high,
	)
	PUNPCKHLQ(
		halves.high,
		halves.high,
	)

	return halves
}

// _LeaveInvalidSSE2 leaves the loop unless every character of both registers is '0' or
// '1'.
//
// Revisions:
//   - 2026-10-21 21:58: initial creation, split out of _DecodeBitsSSE2 (review P31)
func _LeaveInvalidSSE2(pair *_BitPair) {
	ANDL(
		pair.second.valid,
		pair.first.valid,
	)
	NOTL(pair.first.valid)
	ANDL(
		U32(1<<SSE2_LANES-1),
		pair.first.valid,
	)
	JNE(LabelRef("done"))
}

// _BinaryEncodeAVX512 renders sixteen bytes as one hundred and twenty-eight '0' and
// '1' characters per iteration, leading bit first, in EVEX encodings only.
//
// It is _BinaryEncodeAVX2 with a ZMM register: eight bytes are broadcast to every qword
// and one in-lane VPSHUFB gives each byte eight consecutive lanes. The compare writes
// a mask register, and VPMOVM2B turns it back into bytes to subtract from '0'.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _BinaryEncodeAVX512() {
	_Begin(
		"_BinaryEncodeAVX512",
		"_BinaryEncodeAVX512 is _BinaryEncodeAVX2 at sixteen bytes per iteration, in",
		"EVEX encodings only, and returns how many bytes it consumed: a multiple of",
		"sixteen. It needs AVX512BW.",
		"",
		"len(dst) must be at least 8*len(src).",
	)

	var (
		args   = _Load(BINARY_ENCODE_AVX512)
		planes = _PlanesAVX512()
		in     = GP64()
		out    = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_EncodeBitsAVX512(
		planes,
		args,
		in,
		out,
	)

	ADDQ(
		U32(BINARY_ENCODE_AVX512*BYTE_BITS),
		out,
	)
	_Next(
		in,
		BINARY_ENCODE_AVX512,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _PlanesAVX512 emits the tables of the AVX-512 binary encoder and loads them.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation, split out of _BinaryEncodeAVX512 (review P33)
func _PlanesAVX512() *_Planes {
	var (
		masks = _Table(
			"binary_bit_masks_avx512",
			BIT_MASKS,
		)
		table = _Table(
			"binary_replicate_avx512",
			REPLICATE_0,
			REPLICATE_1,
			REPLICATE_2,
			REPLICATE_3,
			REPLICATE_4,
			REPLICATE_5,
			REPLICATE_6,
			REPLICATE_7,
		)
		planes = &_Planes{
			bits:  ZMM(),
			table: ZMM(),
			zeros: _BroadcastAVX512(CHAR_ZERO),
		}
	)

	VPBROADCASTQ(
		masks,
		planes.bits,
	)
	VMOVDQU8(
		table,
		planes.table,
	)

	return planes
}

// _EncodeBitsAVX512 stores the characters of sixteen bytes, eight bytes to a register.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _EncodeBitsAVX512(
	planes *_Planes,
	args *_Args,
	in,
	out reg.Register,
) {
	_SpreadAVX512(
		planes,
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	_SpreadAVX512(
		planes,
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
			Disp:  SECOND_OCTETS,
		},
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  AVX512_LANES,
		},
	)
}

// _SpreadAVX512 turns eight bytes into sixty-four characters and stores them.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _SpreadAVX512(
	planes *_Planes,
	from Mem,
	to Mem,
) {
	var (
		bytes = ZMM()
		lanes = ZMM()
		set   = K()
		ones  = ZMM()
		chars = ZMM()
	)

	VPBROADCASTQ(
		from,
		bytes,
	)
	VPSHUFB(
		planes.table,
		bytes,
		lanes,
	)
	VPANDQ(
		planes.bits,
		lanes,
		lanes,
	)
	VPCMPEQB(
		planes.bits,
		lanes,
		set,
	)
	VPMOVM2B(
		set,
		ones,
	)
	VPSUBB(
		ones,
		planes.zeros,
		chars,
	)
	VMOVDQU8(
		chars,
		to,
	)
}

// _BinaryDecodeAVX512 parses one hundred and twenty-eight '0' and '1' characters into
// sixteen bytes per iteration, leading character first, in EVEX encodings only.
//
// The compares write the bits to a mask register, and KMOVQ moves it to a general
// register. As in _BinaryDecodeAVX2 each run of eight lanes is reversed first, so the
// leading character of a byte lands in its most significant bit.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _BinaryDecodeAVX512() {
	_Begin(
		"_BinaryDecodeAVX512",
		"_BinaryDecodeAVX512 is _BinaryDecodeAVX2 at one hundred and twenty-eight",
		"characters per iteration, in EVEX encodings only, and returns how many",
		"characters it consumed: a multiple of one hundred and twenty-eight, short",
		"of len(src) when a block holds a character that is neither. It needs AVX512BW.",
		"",
		"len(dst) must be at least len(src)/8.",
	)

	var (
		reverse = _Table(
			"binary_reverse_avx512",
			REVERSE_LOW,
			REVERSE_HIGH,
		)
		args  = _Load(BINARY_DECODE_AVX512)
		marks = _MarksAVX512(reverse)
		in    = GP64()
		out   = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)
	_DecodeBitsAVX512(
		marks,
		args,
		in,
		out,
	)

	ADDQ(
		U32(BINARY_DECODE_AVX512/BYTE_BITS),
		out,
	)
	_Next(
		in,
		BINARY_DECODE_AVX512,
		args.limit,
	)

	_ReturnAVX2(in)
}

// _MarksAVX512 broadcasts the constants the AVX-512 binary classifier tests against.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _MarksAVX512(reverse Mem) *_Marks {
	marks := &_Marks{
		one:     _BroadcastAVX512(LOW_BIT),
		ones:    _BroadcastAVX512(CHAR_ONE),
		reverse: ZMM(),
	}

	VBROADCASTI32X4(
		reverse,
		marks.reverse,
	)

	return marks
}

// _DecodeBitsAVX512 gathers one hundred and twenty-eight characters, leaves the loop
// when one is neither '0' nor '1', and stores the sixteen bytes they denote.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _DecodeBitsAVX512(
	marks *_Marks,
	args *_Args,
	in,
	out reg.Register,
) {
	var (
		first = _GatherAVX512(
			marks,
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
			},
		)
		second = _GatherAVX512(
			marks,
			Mem{
				Base:  args.src,
				Index: in,
				Scale: 1,
				Disp:  AVX512_LANES,
			},
		)
	)

	KANDQ(
		second.valid,
		first.valid,
		first.valid,
	)
	_AllLanesAVX512(first.valid)

	MOVQ(
		first.bits,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)
	MOVQ(
		second.bits,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  SECOND_OCTETS,
		},
	)
}

// _GatherAVX512 loads one register of characters and returns the mask of lanes that
// hold '0' or '1', and the sixty-four bits they denote.
//
// A character is valid when setting its low bit gives '1', which is true of '0' and
// '1' and of nothing else.
//
// Revisions:
//   - 2026-10-21 23:56: initial creation (review P33)
func _GatherAVX512(
	marks *_Marks,
	at Mem,
) *_Flags {
	var (
		text   = ZMM()
		lifted = ZMM()
		found  = &_Flags{
			valid: K(),
			bits:  GP64(),
		}
		set = K()
	)

	VMOVDQU8(
		at,
		text,
	)
	VPORQ(
		marks.one,
		text,
		lifted,
	)
	VPCMPEQB(
		marks.ones,
		lifted,
		found.valid,
	)
	VPSHUFB(
		marks.reverse,
		text,
		text,
	)
	VPCMPEQB(
		marks.ones,
		text,
		set,
	)
	KMOVQ(
		set,
		found.bits,
	)

	return found
}
