package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

// A range alphabet - IA5String is 0 to 0x7F, VisibleString 0x20 to 0x7E - is valid when
// every byte x of the text has x - lower <= upper - lower, unsigned. One subtract, one
// unsigned minimum and one compare test a register of bytes, and a byte at or above 0x80
// fails the test with no extra step, because upper is below it. These kernels only check:
// the text is already the octets the encoder writes. RANGE_SIGNATURE is their Go
// signature, which is not the one the conversion kernels share.
const (
	RANGE_SIGNATURE = "func(src []byte, lower, upper byte) int"
)

// _RangeSSE2 emits the SSE2 range check, sixteen bytes per iteration.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _RangeSSE2() {
	_BeginRange(
		"_CheckRangeSSE2",
		"_CheckRangeSSE2 checks that each byte of src is in lower..upper, sixteen bytes",
		"per iteration, and returns how many bytes it checked: a multiple of sixteen,",
		"short of len(src) when a block holds a byte outside the range.",
	)

	var (
		bounds = _LoadBounds(SSE2_LANES)
		lower  = _FillSSE2(bounds.lower)
		span   = _FillSSE2(bounds.span)

		idx = GP64()
	)

	_Clear(idx)
	_Enter(bounds.limit)
	_TestBlockSSE2(
		lower,
		span,
		Mem{
			Base:  bounds.src,
			Index: idx,
			Scale: 1,
		},
	)
	_Next(
		idx,
		SSE2_LANES,
		bounds.limit,
	)
	_Return(idx)
}

// _RangeAVX2 emits the AVX2 range check, thirty-two bytes per iteration.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _RangeAVX2() {
	_BeginRange(
		"_CheckRangeAVX2",
		"_CheckRangeAVX2 is _CheckRangeSSE2 at thirty-two bytes per iteration.",
	)

	var (
		bounds = _LoadBounds(AVX2_LANES)
		lower  = _FillAVX2(bounds.lower)
		span   = _FillAVX2(bounds.span)

		idx = GP64()
	)

	_Clear(idx)
	_Enter(bounds.limit)
	_TestBlockAVX2(
		lower,
		span,
		Mem{
			Base:  bounds.src,
			Index: idx,
			Scale: 1,
		},
	)
	_Next(
		idx,
		AVX2_LANES,
		bounds.limit,
	)
	_ReturnAVX2(idx)
}

// _TestBlockSSE2 loads sixteen bytes and leaves the loop when one is outside the range.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation, split out of _RangeSSE2 (review P28)
func _TestBlockSSE2(
	lower,
	span reg.VecVirtual,
	at Mem,
) {
	text, least := XMM(), XMM()

	// text = byte - lower; least = min(text, span); a lane is in the range when they agree.
	MOVOU(
		at,
		text,
	)
	PSUBB(
		lower,
		text,
	)
	MOVO(
		text,
		least,
	)
	PMINUB(
		span,
		least,
	)
	PCMPEQB(
		text,
		least,
	)
	_AllLanesSSE2(least)
}

// _TestBlockAVX2 loads thirty-two bytes and leaves the loop when one is outside the range.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation, split out of _RangeAVX2 (review P28)
func _TestBlockAVX2(
	lower,
	span reg.VecVirtual,
	at Mem,
) {
	text, diff, least := YMM(), YMM(), YMM()

	// diff = byte - lower; least = min(diff, span); a lane is in the range when they agree.
	VMOVDQU(
		at,
		text,
	)
	VPSUBB(
		lower,
		text,
		diff,
	)
	VPMINUB(
		span,
		diff,
		least,
	)
	VPCMPEQB(
		least,
		diff,
		least,
	)
	_AllLanesYMM(least)
}

// _Bounds are what a range kernel loads: the text, its length rounded down to whole
// blocks, the lower bound, and the span upper - lower.
type _Bounds struct {
	src   reg.Register
	limit reg.Register
	lower reg.GPVirtual
	span  reg.GPVirtual
}

// _BeginRange opens a range kernel. It has its own Go signature, does not split the
// stack, and keeps its slice from escaping.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _BeginRange(
	name string,
	doc ...string,
) {
	TEXT(
		name,
		NOSPLIT,
		RANGE_SIGNATURE,
	)
	Pragma("noescape")
	Doc(doc...)
}

// _LoadBounds reads the text and the two bounds, rounds the length down to whole
// blocks, and turns upper into the span the unsigned compare needs.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _LoadBounds(block int) *_Bounds {
	bounds := &_Bounds{
		src: Load(
			Param("src").Base(),
			GP64(),
		),
		limit: Load(
			Param("src").Len(),
			GP64(),
		),
		lower: GP32(),
		span:  GP32(),
	}

	Load(
		Param("lower"),
		bounds.lower,
	)
	Load(
		Param("upper"),
		bounds.span,
	)
	SUBL(
		bounds.lower,
		bounds.span,
	)
	ANDQ(
		I32(-int32(block)),
		bounds.limit,
	)

	return bounds
}

// _FillSSE2 fills a register with the low byte of a scalar. SSE2 has no byte
// broadcast, so the multiply puts the byte in all four bytes of a dword, and the
// shuffle copies that dword.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _FillSSE2(scalar reg.GPVirtual) reg.VecVirtual {
	var (
		dword  = GP32()
		vector = XMM()
	)

	IMUL3L(
		U32(FOUR_BYTES),
		scalar,
		dword,
	)
	MOVD(
		dword,
		vector,
	)
	PSHUFD(
		U8(0),
		vector,
		vector,
	)

	return vector
}

// _FillAVX2 fills a register with the low byte of a scalar.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _FillAVX2(scalar reg.GPVirtual) reg.VecVirtual {
	var (
		lane   = XMM()
		vector = YMM()
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

// _AllLanesYMM leaves the loop unless every byte of one register is set.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _AllLanesYMM(valid reg.VecVirtual) {
	mask := GP32()

	VPMOVMSKB(
		valid,
		mask,
	)
	NOTL(mask)
	TESTL(
		mask,
		mask,
	)
	JNE(LabelRef("done"))
}

// _RangeAVX512 emits the AVX-512 range check, sixty-four bytes per iteration, EVEX only.
// The test is that of _RangeAVX2; the compare writes a mask register, which
// _AllLanesAVX512 tests.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation (review P33)
func _RangeAVX512() {
	_BeginRange(
		"_CheckRangeAVX512",
		"_CheckRangeAVX512 is _CheckRangeSSE2 at sixty-four bytes per iteration.",
	)

	var (
		bounds = _LoadBounds(AVX512_LANES)
		lower  = _FillAVX512(bounds.lower)
		span   = _FillAVX512(bounds.span)
		idx    = GP64()
	)

	_Clear(idx)
	_Enter(bounds.limit)
	_TestBlockAVX512(
		lower,
		span,
		Mem{
			Base:  bounds.src,
			Index: idx,
			Scale: 1,
		},
	)
	_Next(
		idx,
		AVX512_LANES,
		bounds.limit,
	)
	_ReturnAVX2(idx)
}

// _FillAVX512 fills a ZMM register with the low byte of a scalar, with the EVEX form of
// VPBROADCASTB.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation (review P33)
func _FillAVX512(scalar reg.GPVirtual) reg.VecVirtual {
	vector := ZMM()

	VPBROADCASTB(
		scalar,
		vector,
	)

	return vector
}

// _TestBlockAVX512 loads sixty-four bytes and leaves the loop when one is outside the range.
//
// Revisions:
//   - 2026-10-21 23:52: initial creation (review P33)
func _TestBlockAVX512(
	lower,
	span reg.VecVirtual,
	at Mem,
) {
	var (
		text  = ZMM()
		diff  = ZMM()
		least = ZMM()
		valid = K()
	)

	// diff = byte - lower; least = min(diff, span); a lane is in the range when they agree.
	VMOVDQU8(
		at,
		text,
	)
	VPSUBB(
		lower,
		text,
		diff,
	)
	VPMINUB(
		span,
		diff,
		least,
	)
	VPCMPEQB(
		least,
		diff,
		valid,
	)
	_AllLanesAVX512(valid)
}
