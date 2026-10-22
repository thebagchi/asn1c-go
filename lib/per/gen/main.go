// Command gen builds the text kernels of this package, one assembly file per
// concern: NumericString packing and unpacking (numeric.go), the hexadecimal
// conversions (hex.go), the binary-text conversions (bin.go) and the range check of an
// IA5String or a VisibleString (range.go). This file holds main and what the kernels
// share.
//
// They are one program because they are one idea. A NumericString character is
// a nibble, a hexadecimal character is a nibble, and a binary-text character is
// a bit: every kernel here either splits bytes into fields and looks each up, or
// classifies characters into fields and packs them back. The nibble split and
// the pair pack are written once below and the kernels differ in their tables
// and their classifiers.
//
// One run emits one file. -only names the set to emit, and each family's
// *_amd64.go file carries the go:generate directive that runs the program for
// its set. avo takes its own flags - -out and -pkg - from the same command line.
//
// Every kernel that can fail validates as it goes and stops at the first block
// holding a character outside its alphabet, returning how much it consumed. The
// scalar code in the package takes over from there, which is what reports the
// error - so the message a caller sees is the one it saw before any of this
// existed.
//
// The SSE2 kernels use legacy encodings only and the AVX2 kernels VEX only, and
// the AVX2 ones end in VZEROUPPER; lib/bitbuffer/gen says why. There is no
// AVX-512 rung: validating a ZMM register needs the mask registers or a fold,
// which is a different body rather than a wider one, and there is no machine
// here to run it.
//
// Regenerate with "make generate".
package main

import (
	"flag"
	"log"

	"github.com/mmcloughlin/avo/attr"
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

// Field widths, register widths, and the ASCII the classifiers test against.
// WORD_OCTETS is the size of one word of a DATA table. KERNEL_SIGNATURE is the Go
// signature that every kernel here shares.
const (
	WORD_OCTETS      = 8
	KERNEL_SIGNATURE = "func(dst, src []byte) int"
)

const (
	NIBBLE_BITS  = 4
	BYTE_BITS    = 8
	SSE2_LANES   = 16
	AVX2_LANES   = 32
	AVX512_LANES = 64
	DIGIT_ZERO   = 0x30
	LAST_DIGIT   = 9

	// A dword holding one byte four times, so a byte constant can be
	// broadcast with a dword shuffle where there is no byte broadcast.
	FOUR_BYTES = 0x01010101
	// The word mask that keeps the low nibble of a zero-extended byte.
	NIBBLE_WORDS = 0x000F000F
	// The word mask that keeps the low byte of each word before packing.
	LOW_BYTE_WORDS = 0x00FF00FF
	// Multiplier bytes for VPMADDUBSW, alternating 16 and 1, so each pair of
	// adjacent nibble values sums to first<<4 | second in one instruction.
	PAIR_WEIGHTS = 0x0110011001100110
	// VPERMQ immediate that puts VPACKUSWB's two lanes back in order: the
	// pack leaves qwords as (first.lo, second.lo, first.hi, second.hi) and
	// the store wants (first.lo, first.hi, second.lo, second.hi).
	ORDER_LANES = 0xD8
	// The upper half of a register, for VEXTRACTI128.
	UPPER_HALF = 1
)

// SETS are the kernel sets -only can name, each in the order its file lists
// them.
var (
	SETS = map[string][]func(){
		"numeric": {
			_PackSSE2,
			_PackAVX2,
			_UnpackSSE2,
			_UnpackAVX2,
			_PackAVX512,
			_UnpackAVX512,
		},
		"hex": {
			_HexEncodeAVX2,
			_HexDecodeAVX2,
			_HexEncodeAVX512,
			_HexDecodeAVX512,
		},
		"bin": {
			_BinaryEncodeAVX2,
			_BinaryDecodeAVX2,
			_BinaryEncodeSSE2,
			_BinaryDecodeSSE2,
			_BinaryEncodeAVX512,
			_BinaryDecodeAVX512,
		},
		"range": {
			_RangeSSE2,
			_RangeAVX2,
			_RangeAVX512,
		},
		"septet": {
			_SeptetPackSSE2,
			_SeptetPackAVX2,
			_SeptetSpreadSSE2,
			_SeptetSpreadAVX2,
			_SeptetPackAVX512,
			_SeptetSpreadAVX512,
		},
	}
)

// _Args are the two slices every kernel loads, and the block-rounded source
// length the loop runs to.
type _Args struct {
	dst   reg.Register
	src   reg.Register
	limit reg.Register
}

// _Lanes are what classifying one register of characters yields: which lanes
// hold a character in the alphabet, and the field value of each.
type _Lanes struct {
	valid reg.VecVirtual
	index reg.VecVirtual
}

// _Probe is what testing one register of characters against a range yields:
// the value of each lane relative to the range, and which lanes are inside it.
type _Probe struct {
	value reg.VecVirtual
	match reg.VecVirtual
}

// _Source is one register of packed bytes, and its upper half, which the
// kernels that widen bytes to words handle as a register of its own.
type _Source struct {
	packed reg.VecVirtual
	upper  reg.VecVirtual
}

// main emits the kernel set -only names. The flag is parsed here, before avo
// parses the rest, because the set decides what is emitted and avo only sees
// the result.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 08:40: the hexadecimal and binary kernels, and the shared
//     parts split out to here
//   - 2026-09-24 00:30: one file per set, chosen with -only
//   - 2026-10-21 16:08: the range set (review P28)
func main() {
	only := flag.String(
		"only",
		"",
		"the kernel set to emit: numeric, hex, bin, range or septet",
	)

	flag.Parse()

	kernels, ok := SETS[*only]
	if !ok {
		log.Fatalf(
			"gen: -only must name a kernel set, not %q",
			*only,
		)
	}

	ConstraintExpr("amd64")

	for _, emit := range kernels {
		emit()
	}

	Generate()
}

// _Load reads the two slices and rounds the source length down to whole
// blocks, which is where the loop stops.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
func _Load(block int) *_Args {
	var (
		args = &_Args{
			dst: Load(
				Param("dst").Base(),
				GP64(),
			),
			src: Load(
				Param("src").Base(),
				GP64(),
			),
			limit: Load(
				Param("src").Len(),
				GP64(),
			),
		}
	)

	ANDQ(
		I32(-int32(block)),
		args.limit,
	)

	return args
}

// _Enter opens a bottom-tested loop: it skips the body when there is no whole
// block to run it on, and places the label the bottom branches back to.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _Enter(limit reg.Register) {
	TESTQ(
		limit,
		limit,
	)
	JEQ(LabelRef("done"))
	Label("loop")
}

// _Next advances the loop counter by one block and branches back while blocks
// remain: one taken branch per iteration, where a top-tested loop pays two.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _Next(
	counter reg.Register,
	block int,
	limit reg.Register,
) {
	ADDQ(
		U32(block),
		counter,
	)
	CMPQ(
		counter,
		limit,
	)
	JL(LabelRef("loop"))
}

// _AllLanesSSE2 leaves the loop unless every byte of valid is set.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
func _AllLanesSSE2(valid reg.VecVirtual) {
	mask := GP32()

	PMOVMSKB(
		valid,
		mask,
	)
	NOTL(mask)
	ANDL(
		U32(1<<SSE2_LANES-1),
		mask,
	)
	JNE(LabelRef("done"))
}

// _AllLanesAVX2 leaves the loop unless every byte of both registers is set.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
//   - 2026-09-23 07:40: takes both registers of an iteration
func _AllLanesAVX2(
	first,
	second reg.VecVirtual,
) {
	mask, other := GP32(), GP32()

	VPMOVMSKB(
		first,
		mask,
	)
	VPMOVMSKB(
		second,
		other,
	)
	ANDL(
		other,
		mask,
	)
	NOTL(mask)
	TESTL(
		mask,
		mask,
	)
	JNE(LabelRef("done"))
}

// _SplitAVX2 zero-extends sixteen packed bytes to words and places each
// byte's two nibbles as the word's two bytes - high nibble first - so the
// register reads as thirty-two nibble values in order.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _SplitAVX2(
	nibble reg.VecVirtual,
	packed reg.Register,
) reg.VecVirtual {
	words, high, low, index := YMM(), YMM(), YMM(), YMM()

	VPMOVZXBW(
		packed,
		words,
	)
	VPSRLW(
		U8(NIBBLE_BITS),
		words,
		high,
	)
	VPAND(
		nibble,
		words,
		low,
	)
	VPSLLW(
		U8(BYTE_BITS),
		low,
		low,
	)
	VPOR(
		low,
		high,
		index,
	)

	return index
}

// _PackPairsAVX2 packs two registers of nibble values, sixty-four in all, into
// thirty-two bytes in order.
//
// Each pair of adjacent values becomes first*16 + second in one word. Packing
// both registers' words to bytes interleaves their lanes, and the permute puts
// the four qwords back in order.
//
// Revisions:
//   - 2026-09-23 08:40: initial creation, split out of the NumericString pack
func _PackPairsAVX2(
	pairs,
	first,
	second reg.VecVirtual,
) reg.VecVirtual {
	low, high := YMM(), YMM()

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
		U8(ORDER_LANES),
		low,
		low,
	)

	return low
}

// _BroadcastSSE2 fills a register with one dword, which is how a byte or word
// constant is broadcast without SSSE3.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
func _BroadcastSSE2(value uint32) reg.VecVirtual {
	var (
		scalar = GP32()
		vector = XMM()
	)

	MOVL(
		U32(value),
		scalar,
	)
	MOVD(
		scalar,
		vector,
	)
	PSHUFD(
		U8(0),
		vector,
		vector,
	)

	return vector
}

// _BroadcastAVX2 fills a register with one byte.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
func _BroadcastAVX2(value uint32) reg.VecVirtual {
	var (
		scalar = GP32()
		lane   = XMM()
		vector = YMM()
	)

	MOVL(
		U32(value),
		scalar,
	)
	VMOVD(
		scalar,
		lane,
	)
	VPBROADCASTB(
		lane,
		vector,
	)

	return vector
}

// _BroadcastDwordAVX2 fills a register with one dword.
//
// Revisions:
//   - 2026-09-23 05:31: initial creation
func _BroadcastDwordAVX2(value uint32) reg.VecVirtual {
	var (
		scalar = GP32()
		lane   = XMM()
		vector = YMM()
	)

	MOVL(
		U32(value),
		scalar,
	)
	VMOVD(
		scalar,
		lane,
	)
	VPBROADCASTD(
		lane,
		vector,
	)

	return vector
}

// _Table emits a read-only table of 64-bit words and returns its address. Every
// kernel table is a run of words, so one place writes the GLOBL and its DATA.
//
// Revisions:
//   - 2026-10-20 13:54: initial creation
func _Table(
	name string,
	words ...uint64,
) Mem {
	table := GLOBL(
		name,
		attr.RODATA|attr.NOPTR,
	)

	for idx, word := range words {
		DATA(
			idx*WORD_OCTETS,
			U64(word),
		)
	}

	return table
}

// _Begin opens a kernel. Every kernel here has the same Go signature, does not
// split the stack, and keeps its slices from escaping.
//
// Revisions:
//   - 2026-10-20 13:55: initial creation
func _Begin(
	name string,
	doc ...string,
) {
	TEXT(
		name,
		NOSPLIT,
		KERNEL_SIGNATURE,
	)
	Pragma("noescape")
	Doc(doc...)
}

// _Clear sets each register to zero.
//
// Revisions:
//   - 2026-10-20 13:55: initial creation
func _Clear(registers ...reg.Register) {
	for _, register := range registers {
		XORQ(
			register,
			register,
		)
	}
}

// _Return closes an SSE2 kernel: the done label returns how much it consumed.
//
// Revisions:
//   - 2026-10-20 13:55: initial creation
func _Return(consumed reg.Register) {
	Label("done")
	Store(
		consumed,
		ReturnIndex(0),
	)
	RET()
}

// _ReturnAVX2 closes an AVX2 kernel. VZEROUPPER clears the upper halves first,
// so the SSE code after the call pays no transition penalty.
//
// Revisions:
//   - 2026-10-20 13:55: initial creation
func _ReturnAVX2(consumed reg.Register) {
	Label("done")
	VZEROUPPER()
	Store(
		consumed,
		ReturnIndex(0),
	)
	RET()
}

// _LoadHalvesAVX2 reads thirty-two bytes and extracts the upper sixteen, so the
// two halves can be split into nibbles one after the other.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation
func _LoadHalvesAVX2(at Mem) *_Source {
	source := &_Source{
		packed: YMM(),
		upper:  XMM(),
	}

	VMOVDQU(
		at,
		source.packed,
	)
	VEXTRACTI128(
		U8(UPPER_HALF),
		source.packed,
		source.upper,
	)

	return source
}

// _StoreCharsAVX2 looks each index up in the table and stores the thirty-two
// characters. The caller owns the character register, so that the two stores
// of an iteration reuse one.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation
func _StoreCharsAVX2(
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
	VMOVDQU(
		chars,
		at,
	)
}

// _DigitTestAVX2 subtracts '0' from each lane and finds the lanes that are a
// digit.
//
// Revisions:
//   - 2026-10-20 13:58: initial creation
func _DigitTestAVX2(
	zero,
	nine,
	text reg.VecVirtual,
) *_Probe {
	digit, lower, isDigit := YMM(), YMM(), YMM()

	// digit = text - '0'; it is one when min(digit, 9) == digit.
	VPSUBB(
		zero,
		text,
		digit,
	)
	VPMINUB(
		nine,
		digit,
		lower,
	)
	VPCMPEQB(
		lower,
		digit,
		isDigit,
	)

	return &_Probe{
		value: digit,
		match: isDigit,
	}
}

// _BroadcastAVX512 fills a ZMM register with one byte. The byte goes from a general
// register straight to every lane with the EVEX form of VPBROADCASTB, so no VEX
// instruction runs in an AVX-512 kernel.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation (review P33)
func _BroadcastAVX512(value uint32) reg.VecVirtual {
	var (
		scalar = GP32()
		vector = ZMM()
	)

	MOVL(
		U32(value),
		scalar,
	)
	VPBROADCASTB(
		scalar,
		vector,
	)

	return vector
}

// _AllLanesAVX512 leaves the loop unless every bit of the mask is set. An AVX-512
// compare writes a mask register, not a vector, so there is no VPMOVMSKB: KORTESTQ sets
// the carry flag exactly when the mask is all ones.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation (review P33)
func _AllLanesAVX512(valid reg.OpmaskVirtual) {
	KORTESTQ(
		valid,
		valid,
	)
	JCC(LabelRef("done"))
}
