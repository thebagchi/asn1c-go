// Parameterised VEX encoding.
//
// Measured before assumed: Go's amd64 assembler spells 813 of the 1006 SIMD mnemonics the
// Intel intrinsics guide names, and the 193 it misses are almost all AVX512-FP16, the SSE
// conversions it gives width suffixes, and instructions newer than its tables. **For
// AVX2-era work its coverage is effectively complete**, so this header is not the way to
// reach an everyday instruction - the mnemonic is.
//
// What it is for is the residue: an instruction genuinely absent, or one added to the
// hardware before Go's tables catch up. The usual way to write those - the way minio's
// asm2plan9s emits them - is a fixed BYTE string per instruction with the registers baked
// in, which is one macro per register combination and not a library.
//
// It does not have to be that way. Go's assembler evaluates constant arithmetic inside a
// BYTE operand, including arithmetic on macro parameters, so the VEX prefix can be computed
// from register numbers at assembly time rather than written out by hand. That is what this
// header does: VEX2 and VEX3 below take registers as arguments and build the encoding.
//
// The one operator that does not work is unary NOT - "unexpected ^ evaluating expression" -
// so every inversion here is spelled "(x) ^ 0xF" instead.
//
// Checked against the assembler itself: tools/simd/macro/vex_test.go assembles the same
// instruction through a Go mnemonic and through these macros and compares the results, at
// low and at high register numbers. See README.md.

// Register numbers, for passing to the macros below.
//
// They are spelled YMM and XMM rather than Y and X so that they cannot collide with Go's
// own register names, which a file using these macros still uses for everything else. A
// "#define Y0 0" would quietly break every ordinary instruction naming Y0 in the same file.
#define XMM0   0
#define XMM1   1
#define XMM2   2
#define XMM3   3
#define XMM4   4
#define XMM5   5
#define XMM6   6
#define XMM7   7
#define XMM8   8
#define XMM9   9
#define XMM10 10
#define XMM11 11
#define XMM12 12
#define XMM13 13
#define XMM14 14
#define XMM15 15

#define YMM0   0
#define YMM1   1
#define YMM2   2
#define YMM3   3
#define YMM4   4
#define YMM5   5
#define YMM6   6
#define YMM7   7
#define YMM8   8
#define YMM9   9
#define YMM10 10
#define YMM11 11
#define YMM12 12
#define YMM13 13
#define YMM14 14
#define YMM15 15

// The VEX fields, named as the Intel manual names them, so a spec line copied out of the
// manual - "VEX.256.66.0F3A.W1 CE /r ib" - transcribes one field at a time with nothing to
// work out. tools/simd/catalog carries that spec for every instruction Go knows.
#define VEX_0F   1
#define VEX_0F38 2
#define VEX_0F3A 3

#define VEX_NP 0
#define VEX_66 1
#define VEX_F3 2
#define VEX_F2 3

#define VEX_128 0
#define VEX_256 1

#define VEX_W0 0
#define VEX_W1 1

// VEX3 emits one three-byte-VEX register-to-register instruction.
//
//   C4
//   R X B m m m m m     R and B are the inverted high bits of dst and src2
//   W v v v v L p p     vvvv is the inverted src1
//   opcode
//   1 1 reg rm          mod is 11, so both operands are registers
//
// The inversions are why this has to be arithmetic rather than a lookup table. A register
// above 7 clears a bit in the prefix instead of setting one in ModRM, so an encoder that
// gets it backwards still produces a valid instruction - one that names a different
// register. That is the failure the test's high-register cases exist to catch.
//
// X is always set here because mod is 11: there is no SIB byte and so no index register.
#define VEX3(map, w, src1, len, pp, op, src2, dst)                                       \
	BYTE $0xC4                                                                           \
	BYTE $(0x40 | (map) | ((((dst) ^ 0xF) & 8) << 4) | ((((src2) ^ 0xF) & 8) << 2))      \
	BYTE $(((w) << 7) | ((((src1) ^ 0xF) & 0xF) << 3) | ((len) << 2) | (pp))             \
	BYTE $(op)                                                                           \
	BYTE $(0xC0 | (((dst) & 7) << 3) | ((src2) & 7))

// VEX2 emits the two-byte form, which is one byte shorter and encodes the same instruction
// whenever the map is 0F, W is 0 and neither dst nor src2 is above 7.
//
// It is here for size rather than speed: the processor decodes both identically. Prefer
// VEX3 unless a kernel is tight on instruction bytes, because VEX2 silently mis-encodes a
// register above 7 - it has no bit to put it in.
#define VEX2(src1, len, pp, op, src2, dst)                                               \
	BYTE $0xC5                                                                           \
	BYTE $(((((dst) ^ 0xF) & 8) << 4) | ((((src1) ^ 0xF) & 0xF) << 3) | ((len) << 2) | (pp)) \
	BYTE $(op)                                                                           \
	BYTE $(0xC0 | (((dst) & 7) << 3) | ((src2) & 7))

// GFNI, which Go does spell. These are kept because GF2P8AFFINEQB exercises every field the
// encoder computes at once - three-byte VEX, the 0F3A map, W1 and an immediate - so having
// the mnemonic to compare against makes it the most useful check in the file, not the least.
//
// It is worth having in a bit-oriented codec on its own account: it applies an arbitrary
// 8x8 bit matrix to every byte of a vector in one instruction, which covers bit reversal,
// arbitrary bit permutation within a byte, and multiply-by-constant in GF(2), all of which
// otherwise cost a shift-mask-or chain.

// VGF2P8AFFINEQB dst, src1, src2, imm8 -- VEX.256.66.0F3A.W1 CE /r ib
#define VGF2P8AFFINEQB_256(imm, src2, src1, dst)                                         \
	VEX3(VEX_0F3A, VEX_W1, src1, VEX_256, VEX_66, 0xCE, src2, dst)                       \
	BYTE $(imm)

// VGF2P8AFFINEINVQB dst, src1, src2, imm8 -- VEX.256.66.0F3A.W1 CF /r ib
#define VGF2P8AFFINEINVQB_256(imm, src2, src1, dst)                                      \
	VEX3(VEX_0F3A, VEX_W1, src1, VEX_256, VEX_66, 0xCF, src2, dst)                       \
	BYTE $(imm)

// VGF2P8MULB dst, src1, src2 -- VEX.256.66.0F38.W0 CF /r
#define VGF2P8MULB_256(src2, src1, dst)                                                  \
	VEX3(VEX_0F38, VEX_W0, src1, VEX_256, VEX_66, 0xCF, src2, dst)

// More instructions Go has, kept so the encoder can be checked across the other escape maps
// and both VEX forms. None of these is meant to be used in a kernel: write the mnemonic.

// VPADDB dst, src1, src2 -- VEX.256.66.0F.WIG FC /r
#define VPADDB_256(src2, src1, dst)                                                      \
	VEX3(VEX_0F, VEX_W0, src1, VEX_256, VEX_66, 0xFC, src2, dst)

// VPSHUFB dst, src1, src2 -- VEX.256.66.0F38.WIG 00 /r
#define VPSHUFB_256(src2, src1, dst)                                                     \
	VEX3(VEX_0F38, VEX_W0, src1, VEX_256, VEX_66, 0x00, src2, dst)

// VPXOR dst, src1, src2 -- VEX.256.66.0F.WIG EF /r, through the two-byte form
#define VPXOR_256(src2, src1, dst)                                                       \
	VEX2(src1, VEX_256, VEX_66, 0xEF, src2, dst)
