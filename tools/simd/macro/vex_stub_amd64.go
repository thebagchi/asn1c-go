//go:build amd64

package macro

// The shape of every kernel's input: a 256-bit vector of bytes, and for the
// GFNI ones a matrix per qword. Whether the GFNI kernels may run is
// lib/cpu's HAS_GFNI.
const (
	VECTOR_BYTES    = 32
	MATRIX_BYTES    = 8
	BITS_PER_MATRIX = 8
)

// _AsmAdd adds the two inputs bytewise, written as a Go mnemonic.
//
//go:noescape
func _AsmAdd(dst, lhs, rhs *byte)

// _VexAdd does the same thing through the macros in vex_amd64.h.
//
//go:noescape
func _VexAdd(dst, lhs, rhs *byte)

// _AsmAddHigh adds through registers above 7, written as a Go mnemonic.
//
//go:noescape
func _AsmAddHigh(dst, lhs, rhs *byte)

// _VexAddHigh does the same thing through the macros.
//
//go:noescape
func _VexAddHigh(dst, lhs, rhs *byte)

// _AsmShuffle permutes lhs by rhs, written as a Go mnemonic.
//
//go:noescape
func _AsmShuffle(dst, lhs, rhs *byte)

// _VexShuffle does the same thing through the macros.
//
//go:noescape
func _VexShuffle(dst, lhs, rhs *byte)

// _AsmXor exclusive-ors the two inputs, written as a Go mnemonic.
//
//go:noescape
func _AsmXor(dst, lhs, rhs *byte)

// _VexXor does the same thing through the two-byte VEX macro.
//
//go:noescape
func _VexXor(dst, lhs, rhs *byte)

// _AsmAffine applies the bit matrix in each qword of rhs to every byte of lhs,
// written as a Go mnemonic.
//
//go:noescape
func _AsmAffine(dst, lhs, rhs *byte)

// _VexAffine does the same thing through the macros.
//
//go:noescape
func _VexAffine(dst, lhs, rhs *byte)

// _VexAffineHigh does the same through registers above 7.
//
//go:noescape
func _VexAffineHigh(dst, lhs, rhs *byte)

// _VexMul multiplies the inputs bytewise in GF(2^8), through the macros.
//
//go:noescape
func _VexMul(dst, lhs, rhs *byte)
