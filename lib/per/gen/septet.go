package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

// The 7-bit pack of an UPER IA5String or VisibleString: character i is bits 7i to 7i+6 of
// the field, leading bit first, so eight characters are one 56-bit group of seven octets.
// The pack merges neighbours three times - two characters to a word, two words to a dword,
// two dwords to a qword - and the spread splits them again. Each merge needs no mask: a
// shift left and back right drops the bits above the field, so SSE2 and AVX2 run the same
// steps. Only the byte order differs: AVX2 uses VPSHUFB, and SSE2, which has no PSHUFB,
// turns each qword through a general register with BSWAPQ.
const (
	SEPTET_SSE2_CHARS = 16
	SEPTET_SSE2_BYTES = 14
	SEPTET_AVX2_CHARS = 32
	SEPTET_AVX2_BYTES = 28
	// The AVX-512 block is twice the AVX2 block: four 128-bit lanes of two groups each.
	SEPTET_AVX512_CHARS = 64
	SEPTET_AVX512_BYTES = 56
	SEPTET_LANES        = 4
	// The octets of one group of eight characters, and where the second group of a
	// 16-character register starts.
	SEPTET_GROUP_BYTES = 7
	// The offset of the second lane of a 256-bit register: two groups of seven octets.
	SEPTET_LANE_OFFSET = 14
	// The widths of the three merges: a character, two characters, four characters.
	SEPTET_CHAR_BITS = 7
	SEPTET_PAIR_BITS = 14
	SEPTET_QUAD_BITS = 28
	WORD_BITS        = 16
	DWORD_BITS       = 32
	QWORD_BITS       = 64
	HALF_REGISTER    = 8
	// The VPSHUFB orders of a lane: two qwords to fourteen octets, high octet first, and
	// two groups of seven octets back to two qwords.
	SEPTET_PACK_LOW    = 0x0E00010203040506
	SEPTET_PACK_HIGH   = 0x808008090A0B0C0D
	SEPTET_SPREAD_LOW  = 0x8000010203040506
	SEPTET_SPREAD_HIGH = 0x800708090A0B0C0D
)

// _SeptetPackSSE2 emits the SSE2 7-bit pack, sixteen characters to fourteen octets per iteration.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetPackSSE2() {
	_Begin(
		"_PackSeptetsSSE2",
		"_PackSeptetsSSE2 packs the 7-bit characters of src into dst, leading bit first,",
		"sixteen characters per iteration, and returns how many characters it consumed:",
		"a multiple of sixteen.",
		"",
		"len(dst) must be at least 14*(len(src)/16)+1: "+
			"each group is stored as eight octets.",
	)

	var (
		args = _Load(SEPTET_SSE2_CHARS)
		in   = GP64()
		out  = GP64()
		text = XMM()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)

	MOVOU(
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		text,
	)
	_SeptetMergeSSE2(text)
	_SeptetStoreSSE2(
		text,
		args,
		out,
	)

	ADDQ(
		U32(SEPTET_SSE2_BYTES),
		out,
	)
	_Next(
		in,
		SEPTET_SSE2_CHARS,
		args.limit,
	)

	_Return(in)
}

// _SeptetMergeSSE2 merges sixteen characters into two qwords of 56 bits each: character 0 at the
// top of the first.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetMergeSSE2(text reg.VecVirtual) {
	high := XMM()

	// Each step: the even element moves up by the width of the odd one, which comes down.
	MOVO(
		text,
		high,
	)
	PSRLW(
		U8(BYTE_BITS),
		high,
	)
	PSLLW(
		U8(BYTE_BITS),
		text,
	)
	PSRLW(
		U8(BYTE_BITS-SEPTET_CHAR_BITS),
		text,
	)
	POR(
		high,
		text,
	)

	_SeptetMergeWordsSSE2(
		text,
		high,
	)
}

// _SeptetMergeWordsSSE2 merges the words of text into dwords, and the dwords into qwords.
//
// Revisions:
//   - 2026-10-21 23:29: initial creation, split out of _SeptetMergeSSE2 (review P32)
func _SeptetMergeWordsSSE2(
	text,
	tmp reg.VecVirtual,
) {
	MOVO(
		text,
		tmp,
	)
	PSRLL(
		U8(WORD_BITS),
		tmp,
	)
	PSLLL(
		U8(WORD_BITS),
		text,
	)
	PSRLL(
		U8(WORD_BITS-SEPTET_PAIR_BITS),
		text,
	)
	POR(
		tmp,
		text,
	)

	MOVO(
		text,
		tmp,
	)
	PSRLQ(
		U8(DWORD_BITS),
		tmp,
	)
	PSLLQ(
		U8(DWORD_BITS),
		text,
	)
	PSRLQ(
		U8(DWORD_BITS-SEPTET_QUAD_BITS),
		text,
	)
	POR(
		tmp,
		text,
	)
}

// _SeptetStoreSSE2 stores the two 56-bit qwords of text as fourteen octets, high octet
// first. Each qword goes through a general register: shifted up one octet and swapped, it
// is the seven octets and a zero, and the second store covers the zero of the first.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetStoreSSE2(
	text reg.VecVirtual,
	args *_Args,
	out reg.Register,
) {
	group := GP64()

	MOVQ(
		text,
		group,
	)
	_SeptetStoreGroup(
		group,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)

	PSRLDQ(
		U8(HALF_REGISTER),
		text,
	)
	MOVQ(
		text,
		group,
	)
	_SeptetStoreGroup(
		group,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
			Disp:  SEPTET_GROUP_BYTES,
		},
	)
}

// _SeptetStoreGroup stores the 56-bit group in a general register as seven octets, high octet
// first, and one zero octet after them.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetStoreGroup(
	group reg.Register,
	at Mem,
) {
	SHLQ(
		U8(BYTE_BITS),
		group,
	)
	BSWAPQ(group)
	MOVQ(
		group,
		at,
	)
}

// _SeptetPackAVX2 emits the AVX2 7-bit pack, thirty-two characters to twenty-eight octets per
// iteration.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetPackAVX2() {
	_Begin(
		"_PackSeptetsAVX2",
		"_PackSeptetsAVX2 is _PackSeptetsSSE2 at thirty-two characters per iteration: it",
		"returns a multiple of thirty-two.",
		"",
		"len(dst) must be at least 28*(len(src)/32)+2: "+
			"each lane is stored as sixteen octets.",
	)

	var (
		order = _Table(
			"septet_pack_order",
			SEPTET_PACK_LOW,
			SEPTET_PACK_HIGH,
		)
		args    = _Load(SEPTET_AVX2_CHARS)
		shuffle = YMM()
		in      = GP64()
		out     = GP64()
	)

	VBROADCASTI128(
		order,
		shuffle,
	)
	_Clear(
		in,
		out,
	)
	_Enter(args.limit)

	_SeptetPackBlockAVX2(
		args,
		shuffle,
		in,
		out,
	)

	_ReturnAVX2(in)
}

// _SeptetPackBlockAVX2 packs thirty-two characters into twenty-eight octets, and moves both
// offsets on to the next block.
//
// Revisions:
//   - 2026-10-21 23:29: initial creation, split out of _SeptetPackAVX2 (review P32)
func _SeptetPackBlockAVX2(
	args *_Args,
	shuffle reg.VecVirtual,
	in,
	out reg.Register,
) {
	text := YMM()

	VMOVDQU(
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		text,
	)
	_SeptetMergeAVX2(text)
	_SeptetStoreAVX2(
		shuffle,
		text,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)

	ADDQ(
		U32(SEPTET_AVX2_BYTES),
		out,
	)
	_Next(
		in,
		SEPTET_AVX2_CHARS,
		args.limit,
	)
}

// _SeptetMergeAVX2 is _SeptetMergeSSE2 on a register of thirty-two characters.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetMergeAVX2(text reg.VecVirtual) {
	high := YMM()

	VPSRLW(
		U8(BYTE_BITS),
		text,
		high,
	)
	VPSLLW(
		U8(BYTE_BITS),
		text,
		text,
	)
	VPSRLW(
		U8(BYTE_BITS-SEPTET_CHAR_BITS),
		text,
		text,
	)
	VPOR(
		high,
		text,
		text,
	)

	_SeptetMergeWordsAVX2(
		text,
		high,
	)
}

// _SeptetMergeWordsAVX2 is _SeptetMergeWordsSSE2 on a register of thirty-two characters.
//
// Revisions:
//   - 2026-10-21 23:29: initial creation, split out of _SeptetMergeAVX2 (review P32)
func _SeptetMergeWordsAVX2(
	text,
	tmp reg.VecVirtual,
) {
	VPSRLD(
		U8(WORD_BITS),
		text,
		tmp,
	)
	VPSLLD(
		U8(WORD_BITS),
		text,
		text,
	)
	VPSRLD(
		U8(WORD_BITS-SEPTET_PAIR_BITS),
		text,
		text,
	)
	VPOR(
		tmp,
		text,
		text,
	)

	VPSRLQ(
		U8(DWORD_BITS),
		text,
		tmp,
	)
	VPSLLQ(
		U8(DWORD_BITS),
		text,
		text,
	)
	VPSRLQ(
		U8(DWORD_BITS-SEPTET_QUAD_BITS),
		text,
		text,
	)
	VPOR(
		tmp,
		text,
		text,
	)
}

// _SeptetStoreAVX2 puts the two groups of each lane in order as fourteen octets, high octet
// first, and stores the two lanes fourteen octets apart; the second store covers the two
// zero octets of the first.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetStoreAVX2(
	shuffle,
	text reg.VecVirtual,
	at Mem,
) {
	upper := XMM()

	VPSHUFB(
		shuffle,
		text,
		text,
	)
	VEXTRACTI128(
		U8(UPPER_HALF),
		text,
		upper,
	)
	VMOVDQU(
		text.AsX(),
		at,
	)
	VMOVDQU(
		upper,
		at.Offset(SEPTET_LANE_OFFSET),
	)
}

// _SeptetSpreadSSE2 emits the SSE2 7-bit spread, fourteen octets to sixteen characters per
// iteration.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetSpreadSSE2() {
	_Begin(
		"_SpreadSeptetsSSE2",
		"_SpreadSeptetsSSE2 spreads 7-bit characters, leading bit first, from src into "+
			"the",
		"octets of dst, sixteen characters per iteration, and returns how many "+
			"characters it",
		"wrote: a multiple of sixteen, no more than len(dst).",
		"",
		"len(src) must be at least 14*(len(dst)/16)+1: "+
			"each group is read as eight octets.",
	)

	var (
		args = _SeptetLoad(SEPTET_SSE2_CHARS)
		in   = GP64()
		out  = GP64()
	)

	_Clear(
		in,
		out,
	)
	_Enter(args.limit)

	text := _SeptetLoadSSE2(
		args,
		in,
	)
	_SeptetSplitSSE2(text)
	MOVOU(
		text,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)

	ADDQ(
		U32(SEPTET_SSE2_BYTES),
		in,
	)
	_Next(
		out,
		SEPTET_SSE2_CHARS,
		args.limit,
	)

	_Return(out)
}

// _SeptetLoad reads the two slices of a spread kernel and rounds the length of dst down to
// whole blocks, which is where its loop stops: a spread counts the characters it writes.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetLoad(block int) *_Args {
	args := &_Args{
		dst: Load(
			Param("dst").Base(),
			GP64(),
		),
		src: Load(
			Param("src").Base(),
			GP64(),
		),
		limit: Load(
			Param("dst").Len(),
			GP64(),
		),
	}

	ANDQ(
		I32(-int32(block)),
		args.limit,
	)

	return args
}

// _SeptetLoadSSE2 reads two groups of seven octets into the two qwords of a register, each
// as the number its octets make, high octet first.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetLoadSSE2(
	args *_Args,
	in reg.Register,
) reg.VecVirtual {
	var (
		first = _SeptetLoadGroup(Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		})
		second = _SeptetLoadGroup(Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
			Disp:  SEPTET_GROUP_BYTES,
		})
	)

	PUNPCKLQDQ(
		second,
		first,
	)

	return first
}

// _SeptetLoadGroup reads eight octets, keeps the first seven as one 56-bit number, high octet
// first, and returns it in the low qword of a register.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetLoadGroup(at Mem) reg.VecVirtual {
	var (
		group  = GP64()
		vector = XMM()
	)

	MOVQ(
		at,
		group,
	)
	BSWAPQ(group)
	SHRQ(
		U8(BYTE_BITS),
		group,
	)
	MOVQ(
		group,
		vector,
	)

	return vector
}

// _SeptetSplitSSE2 splits two qwords of 56 bits into sixteen characters, the reverse of
// _SeptetMergeSSE2. Each step: the upper element comes down, and the lower one moves up into the
// next element after a shift left and back right that drops the bits above it.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetSplitSSE2(text reg.VecVirtual) {
	low := XMM()

	MOVO(
		text,
		low,
	)
	PSRLQ(
		U8(SEPTET_QUAD_BITS),
		text,
	)
	PSLLQ(
		U8(QWORD_BITS-SEPTET_QUAD_BITS),
		low,
	)
	PSRLQ(
		U8(DWORD_BITS-SEPTET_QUAD_BITS),
		low,
	)
	POR(
		low,
		text,
	)

	_SeptetSplitDwordsSSE2(
		text,
		low,
	)
}

// _SeptetSplitDwordsSSE2 splits the dwords of text into words, and the words into characters.
//
// Revisions:
//   - 2026-10-21 23:29: initial creation, split out of _SeptetSplitSSE2 (review P32)
func _SeptetSplitDwordsSSE2(
	text,
	tmp reg.VecVirtual,
) {
	MOVO(
		text,
		tmp,
	)
	PSRLL(
		U8(SEPTET_PAIR_BITS),
		text,
	)
	PSLLL(
		U8(DWORD_BITS-SEPTET_PAIR_BITS),
		tmp,
	)
	PSRLL(
		U8(WORD_BITS-SEPTET_PAIR_BITS),
		tmp,
	)
	POR(
		tmp,
		text,
	)

	MOVO(
		text,
		tmp,
	)
	PSRLW(
		U8(SEPTET_CHAR_BITS),
		text,
	)
	PSLLW(
		U8(WORD_BITS-SEPTET_CHAR_BITS),
		tmp,
	)
	PSRLW(
		U8(BYTE_BITS-SEPTET_CHAR_BITS),
		tmp,
	)
	POR(
		tmp,
		text,
	)
}

// _SeptetSpreadAVX2 emits the AVX2 7-bit spread, twenty-eight octets to thirty-two characters
// per iteration.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetSpreadAVX2() {
	_Begin(
		"_SpreadSeptetsAVX2",
		"_SpreadSeptetsAVX2 is _SpreadSeptetsSSE2 at thirty-two characters per iteration:",
		"it returns a multiple of thirty-two.",
		"",
		"len(src) must be at least 28*(len(dst)/32)+2: "+
			"each lane is read as sixteen octets.",
	)

	var (
		order = _Table(
			"septet_spread_order",
			SEPTET_SPREAD_LOW,
			SEPTET_SPREAD_HIGH,
		)
		args    = _SeptetLoad(SEPTET_AVX2_CHARS)
		shuffle = YMM()
		in      = GP64()
		out     = GP64()
	)

	VBROADCASTI128(
		order,
		shuffle,
	)
	_Clear(
		in,
		out,
	)
	_Enter(args.limit)

	_SeptetSpreadBlockAVX2(
		args,
		shuffle,
		in,
		out,
	)

	_ReturnAVX2(out)
}

// _SeptetSpreadBlockAVX2 spreads twenty-eight octets into thirty-two characters, and moves
// both offsets on to the next block.
//
// Revisions:
//   - 2026-10-21 23:29: initial creation, split out of _SeptetSpreadAVX2 (review P32)
func _SeptetSpreadBlockAVX2(
	args *_Args,
	shuffle reg.VecVirtual,
	in,
	out reg.Register,
) {
	var (
		text = YMM()
		at   = Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		}
	)

	VMOVDQU(
		at,
		text.AsX(),
	)
	VINSERTI128(
		U8(UPPER_HALF),
		at.Offset(SEPTET_LANE_OFFSET),
		text,
		text,
	)
	VPSHUFB(
		shuffle,
		text,
		text,
	)
	_SeptetSplitAVX2(text)
	VMOVDQU(
		text,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)

	ADDQ(
		U32(SEPTET_AVX2_BYTES),
		in,
	)
	_Next(
		out,
		SEPTET_AVX2_CHARS,
		args.limit,
	)
}

// _SeptetSplitAVX2 is _SeptetSplitSSE2 on a register of four qwords.
//
// Revisions:
//   - 2026-10-21 22:02: initial creation (review P32)
func _SeptetSplitAVX2(text reg.VecVirtual) {
	low := YMM()

	VPSLLQ(
		U8(QWORD_BITS-SEPTET_QUAD_BITS),
		text,
		low,
	)
	VPSRLQ(
		U8(DWORD_BITS-SEPTET_QUAD_BITS),
		low,
		low,
	)
	VPSRLQ(
		U8(SEPTET_QUAD_BITS),
		text,
		text,
	)
	VPOR(
		low,
		text,
		text,
	)

	_SeptetSplitDwordsAVX2(
		text,
		low,
	)
}

// _SeptetSplitDwordsAVX2 is _SeptetSplitDwordsSSE2 on a register of four qwords.
//
// Revisions:
//   - 2026-10-21 23:29: initial creation, split out of _SeptetSplitAVX2 (review P32)
func _SeptetSplitDwordsAVX2(
	text,
	tmp reg.VecVirtual,
) {
	VPSLLD(
		U8(DWORD_BITS-SEPTET_PAIR_BITS),
		text,
		tmp,
	)
	VPSRLD(
		U8(WORD_BITS-SEPTET_PAIR_BITS),
		tmp,
		tmp,
	)
	VPSRLD(
		U8(SEPTET_PAIR_BITS),
		text,
		text,
	)
	VPOR(
		tmp,
		text,
		text,
	)

	VPSLLW(
		U8(WORD_BITS-SEPTET_CHAR_BITS),
		text,
		tmp,
	)
	VPSRLW(
		U8(BYTE_BITS-SEPTET_CHAR_BITS),
		tmp,
		tmp,
	)
	VPSRLW(
		U8(SEPTET_CHAR_BITS),
		text,
		text,
	)
	VPOR(
		tmp,
		text,
		text,
	)
}

// _SeptetPackAVX512 emits the AVX-512 7-bit pack, sixty-four characters to fifty-six octets
// per iteration. It is _SeptetPackAVX2 on four lanes, in EVEX forms only.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _SeptetPackAVX512() {
	_Begin(
		"_PackSeptetsAVX512",
		"_PackSeptetsAVX512 is _PackSeptetsSSE2 at sixty-four characters per iteration:",
		"it returns a multiple of sixty-four.",
		"",
		"len(dst) must be at least 56*(len(src)/64)+2: "+
			"each lane is stored as sixteen octets.",
	)

	var (
		order = _Table(
			"septet_pack_order_avx512",
			SEPTET_PACK_LOW,
			SEPTET_PACK_HIGH,
		)
		args    = _Load(SEPTET_AVX512_CHARS)
		shuffle = ZMM()
		in      = GP64()
		out     = GP64()
	)

	VBROADCASTI32X4(
		order,
		shuffle,
	)
	_Clear(
		in,
		out,
	)
	_Enter(args.limit)

	_SeptetPackBlockAVX512(
		args,
		shuffle,
		in,
		out,
	)

	_ReturnAVX2(in)
}

// _SeptetPackBlockAVX512 packs sixty-four characters into fifty-six octets, and moves both
// offsets on to the next block.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _SeptetPackBlockAVX512(
	args *_Args,
	shuffle reg.VecVirtual,
	in,
	out reg.Register,
) {
	text := ZMM()

	VMOVDQU8(
		Mem{
			Base:  args.src,
			Index: in,
			Scale: 1,
		},
		text,
	)
	_SeptetMergeAVX512(text)
	VPSHUFB(
		shuffle,
		text,
		text,
	)

	// Each store covers the two zero octets of the one before it, so they go in order.
	for lane := range SEPTET_LANES {
		VEXTRACTI32X4(
			U8(lane),
			text,
			Mem{
				Base:  args.dst,
				Index: out,
				Scale: 1,
				Disp:  lane * SEPTET_LANE_OFFSET,
			},
		)
	}

	ADDQ(
		U32(SEPTET_AVX512_BYTES),
		out,
	)
	_Next(
		in,
		SEPTET_AVX512_CHARS,
		args.limit,
	)
}

// _SeptetMergeAVX512 is _SeptetMergeAVX2 on a register of sixty-four characters. VPORQ is
// the EVEX spelling of the bitwise or.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _SeptetMergeAVX512(text reg.VecVirtual) {
	high := ZMM()

	VPSRLW(
		U8(BYTE_BITS),
		text,
		high,
	)
	VPSLLW(
		U8(BYTE_BITS),
		text,
		text,
	)
	VPSRLW(
		U8(BYTE_BITS-SEPTET_CHAR_BITS),
		text,
		text,
	)
	VPORQ(
		high,
		text,
		text,
	)

	_SeptetMergeWordsAVX512(
		text,
		high,
	)
}

// _SeptetMergeWordsAVX512 is _SeptetMergeWordsAVX2 on a register of sixty-four characters.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _SeptetMergeAVX512 (review P33)
func _SeptetMergeWordsAVX512(
	text,
	high reg.VecVirtual,
) {
	VPSRLD(
		U8(WORD_BITS),
		text,
		high,
	)
	VPSLLD(
		U8(WORD_BITS),
		text,
		text,
	)
	VPSRLD(
		U8(WORD_BITS-SEPTET_PAIR_BITS),
		text,
		text,
	)
	VPORQ(
		high,
		text,
		text,
	)

	VPSRLQ(
		U8(DWORD_BITS),
		text,
		high,
	)
	VPSLLQ(
		U8(DWORD_BITS),
		text,
		text,
	)
	VPSRLQ(
		U8(DWORD_BITS-SEPTET_QUAD_BITS),
		text,
		text,
	)
	VPORQ(
		high,
		text,
		text,
	)
}

// _SeptetSpreadAVX512 emits the AVX-512 7-bit spread, fifty-six octets to sixty-four
// characters per iteration. It is _SeptetSpreadAVX2 on four lanes, in EVEX forms only.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _SeptetSpreadAVX512() {
	_Begin(
		"_SpreadSeptetsAVX512",
		"_SpreadSeptetsAVX512 is _SpreadSeptetsSSE2 at sixty-four characters per",
		"iteration: it returns a multiple of sixty-four.",
		"",
		"len(src) must be at least 56*(len(dst)/64)+2: "+
			"each lane is read as sixteen octets.",
	)

	var (
		order = _Table(
			"septet_spread_order_avx512",
			SEPTET_SPREAD_LOW,
			SEPTET_SPREAD_HIGH,
		)
		args    = _SeptetLoad(SEPTET_AVX512_CHARS)
		shuffle = ZMM()
		in      = GP64()
		out     = GP64()
	)

	VBROADCASTI32X4(
		order,
		shuffle,
	)
	_Clear(
		in,
		out,
	)
	_Enter(args.limit)

	_SeptetSpreadBlockAVX512(
		args,
		shuffle,
		in,
		out,
	)

	_ReturnAVX2(out)
}

// _SeptetSpreadBlockAVX512 spreads fifty-six octets into sixty-four characters, and moves
// both offsets on to the next block.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _SeptetSpreadBlockAVX512(
	args *_Args,
	shuffle reg.VecVirtual,
	in,
	out reg.Register,
) {
	text := _SeptetLoadAVX512(Mem{
		Base:  args.src,
		Index: in,
		Scale: 1,
	})

	VPSHUFB(
		shuffle,
		text,
		text,
	)
	_SeptetSplitAVX512(text)
	VMOVDQU8(
		text,
		Mem{
			Base:  args.dst,
			Index: out,
			Scale: 1,
		},
	)

	ADDQ(
		U32(SEPTET_AVX512_BYTES),
		in,
	)
	_Next(
		out,
		SEPTET_AVX512_CHARS,
		args.limit,
	)
}

// _SeptetLoadAVX512 reads four lanes of sixteen octets, fourteen octets apart, into one
// register. The broadcast puts the first lane in all four, and the inserts replace the
// rest. An XMM load would need AVX512VL, so no instruction here is narrower than AVX512F
// or BW.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _SeptetSpreadBlockAVX512 (review P33)
func _SeptetLoadAVX512(at Mem) reg.VecVirtual {
	text := ZMM()

	VBROADCASTI32X4(
		at,
		text,
	)

	for lane := 1; lane < SEPTET_LANES; lane++ {
		VINSERTI32X4(
			U8(lane),
			at.Offset(lane*SEPTET_LANE_OFFSET),
			text,
			text,
		)
	}

	return text
}

// _SeptetSplitAVX512 is _SeptetSplitAVX2 on a register of eight qwords.
//
// Revisions:
//   - 2026-10-21 23:57: initial creation (review P33)
func _SeptetSplitAVX512(text reg.VecVirtual) {
	low := ZMM()

	VPSLLQ(
		U8(QWORD_BITS-SEPTET_QUAD_BITS),
		text,
		low,
	)
	VPSRLQ(
		U8(DWORD_BITS-SEPTET_QUAD_BITS),
		low,
		low,
	)
	VPSRLQ(
		U8(SEPTET_QUAD_BITS),
		text,
		text,
	)
	VPORQ(
		low,
		text,
		text,
	)

	_SeptetSplitDwordsAVX512(
		text,
		low,
	)
}

// _SeptetSplitDwordsAVX512 is _SeptetSplitDwordsAVX2 on a register of eight qwords.
//
// Revisions:
//   - 2026-10-22 00:01: initial creation, split out of _SeptetSplitAVX512 (review P33)
func _SeptetSplitDwordsAVX512(
	text,
	low reg.VecVirtual,
) {
	VPSLLD(
		U8(DWORD_BITS-SEPTET_PAIR_BITS),
		text,
		low,
	)
	VPSRLD(
		U8(WORD_BITS-SEPTET_PAIR_BITS),
		low,
		low,
	)
	VPSRLD(
		U8(SEPTET_PAIR_BITS),
		text,
		text,
	)
	VPORQ(
		low,
		text,
		text,
	)

	VPSLLW(
		U8(WORD_BITS-SEPTET_CHAR_BITS),
		text,
		low,
	)
	VPSRLW(
		U8(BYTE_BITS-SEPTET_CHAR_BITS),
		low,
		low,
	)
	VPSRLW(
		U8(SEPTET_CHAR_BITS),
		text,
		text,
	)
	VPORQ(
		low,
		text,
		text,
	)
}
