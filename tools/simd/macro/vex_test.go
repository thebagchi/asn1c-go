//go:build amd64

package macro_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
	"github.com/thebagchi/asn1c-go/tools/simd/macro"
)

// The pairs that must agree. Each is one operation written twice, once as a Go mnemonic and
// once through the macros in vex_amd64.h, so a disagreement is an encoder defect and
// nothing else.
//
// They are chosen for the fields the encoder computes rather than copies: all three escape
// maps, both VEX forms, and registers on both sides of 7.
var (
	VEX_PAIRS = []struct {
		name string
		from func(dst, lhs, rhs *byte)
		made func(dst, lhs, rhs *byte)
	}{
		{name: "VPADDB/0F/low", from: macro.ASM_ADD, made: macro.VEX_ADD},
		{name: "VPADDB/0F/high", from: macro.ASM_ADD_HIGH, made: macro.VEX_ADD_HIGH},
		{name: "VPSHUFB/0F38/low", from: macro.ASM_SHUFFLE, made: macro.VEX_SHUFFLE},
		{name: "VPXOR/two-byte-vex/low", from: macro.ASM_XOR, made: macro.VEX_XOR},
		{name: "GF2P8AFFINEQB/0F3A/W1", from: macro.ASM_AFFINE, made: macro.VEX_AFFINE},
	}
)

// TestVexMacroMatchesAssembler runs each operation both ways and compares the results.
//
// This is the check that makes the header usable. A hand-written BYTE string is verified
// once, by whoever wrote it; a macro that computes the encoding is verified for every
// register combination it is given, and the high-register cases are the ones that matter -
// a register above 7 clears a bit in the VEX prefix rather than setting one in ModRM, so an
// encoder that inverts it wrongly still emits a valid instruction naming a different
// register, which no amount of reading the bytes will show.
func TestVexMacroMatchesAssembler(t *testing.T) {
	t.Parallel()

	if !cpu.HAS_AVX2 {
		t.Skip("no AVX2 on this processor")
	}

	for _, pair := range VEX_PAIRS {
		t.Run(pair.name, func(t *testing.T) {
			t.Parallel()

			lhs, rhs := _Inputs()

			var (
				want [macro.VECTOR_BYTES]byte
				got  [macro.VECTOR_BYTES]byte
			)

			pair.from(&want[0], &lhs[0], &rhs[0])
			pair.made(&got[0], &lhs[0], &rhs[0])

			if want != got {
				t.Errorf("mnemonic gave %x, macro gave %x", want, got)
			}
		})
	}
}

// TestVexMacroMatchesIntelPseudocode checks the GFNI kernels against a written-out model.
//
// The assembler comparison above says the macro encodes what Go's mnemonic encodes. It does
// not say either of them computes what Intel documents, because both would agree on a
// misunderstanding of the operand order. This checks the other thing: that the bytes coming
// out are the affine transform the manual describes, with the matrix and the vector the way
// round the manual has them.
func TestVexMacroMatchesIntelPseudocode(t *testing.T) {
	t.Parallel()

	if !cpu.HAS_GFNI {
		t.Skip("no GFNI on this processor")
	}

	cases := []struct {
		name   string
		kernel func(dst, lhs, rhs *byte)
	}{
		{name: "low registers", kernel: macro.VEX_AFFINE},
		{name: "high registers", kernel: macro.VEX_AFFINE_H},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			lhs, rhs := _Inputs()

			var (
				got  [macro.VECTOR_BYTES]byte
				want = _AffineModel(lhs, rhs)
			)

			item.kernel(&got[0], &lhs[0], &rhs[0])

			if want != got {
				t.Errorf("GF2P8AFFINEQB gave %x, model says %x", got, want)
			}
		})
	}
}

// TestVexMultiplyIsNotIdentity guards against a kernel that silently does nothing.
//
// A macro that expanded to the wrong opcode could still assemble and still return the input
// unchanged, which every comparison against a model of the *same* wrong thing would pass.
// Checking that the result differs from both inputs is crude, but it is independent.
func TestVexMultiplyIsNotIdentity(t *testing.T) {
	t.Parallel()

	if !cpu.HAS_GFNI {
		t.Skip("no GFNI on this processor")
	}

	var (
		got      [macro.VECTOR_BYTES]byte
		lhs, rhs = _Inputs()
	)

	macro.VEX_MUL(&got[0], &lhs[0], &rhs[0])

	if got == lhs || got == rhs {
		t.Errorf("GF2P8MULB returned an input unchanged: %x", got)
	}
}

// _Inputs returns the two vectors every kernel is run over.
//
// The values are fixed rather than random so that a failure is reproducible from the test
// name alone, and they are chosen to put a different value in every byte lane: a kernel
// that read the wrong lane would otherwise pass on a vector of equal bytes.
func _Inputs() ([macro.VECTOR_BYTES]byte, [macro.VECTOR_BYTES]byte) {
	var (
		lhs [macro.VECTOR_BYTES]byte
		rhs [macro.VECTOR_BYTES]byte
	)

	for idx := range lhs {
		lhs[idx] = byte(idx * 7)
		rhs[idx] = byte(idx*3 + 1)
	}

	return lhs, rhs
}

// _AffineModel is GF2P8AFFINEQB with an immediate of zero, written the slow obvious way.
//
// For every byte of lhs it treats the corresponding qword of rhs as an 8x8 bit matrix over
// GF(2) and multiplies, which is a parity of an AND per output bit. Row order is reversed
// against bit order, which is the detail the hardware and a careless model disagree on.
func _AffineModel(lhs, rhs [macro.VECTOR_BYTES]byte) [macro.VECTOR_BYTES]byte {
	var (
		out [macro.VECTOR_BYTES]byte
	)

	for lane := 0; lane < macro.VECTOR_BYTES/macro.MATRIX_BYTES; lane++ {
		var (
			base   = lane * macro.MATRIX_BYTES
			matrix = rhs[base : base+macro.MATRIX_BYTES]
		)

		for idx := range macro.MATRIX_BYTES {
			out[base+idx] = _AffineByte(matrix, lhs[base+idx])
		}
	}

	return out
}

// _AffineByte applies one 8x8 bit matrix to one byte.
func _AffineByte(matrix []byte, value byte) byte {
	var (
		out byte
	)

	for bit := range macro.BITS_PER_MATRIX {
		if _Parity(matrix[macro.BITS_PER_MATRIX-1-bit]&value) == 1 {
			out |= 1 << bit
		}
	}

	return out
}

// _Parity returns the exclusive-or of every bit of a byte.
func _Parity(value byte) byte {
	var (
		out byte
	)

	for ; value != 0; value >>= 1 {
		out ^= value & 1
	}

	return out
}
