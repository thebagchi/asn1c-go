//go:build amd64

package macro

// Test access to the VEX kernels, which are unexported because nothing outside this package
// has any reason to call them: they exist only to be compared against each other.
//
// This file is compiled only under test, so it lets vex_test.go live in the external test
// package - where go.md wants it - without any of these becoming part of the package's
// surface.
var (
	ASM_ADD      = _AsmAdd
	VEX_ADD      = _VexAdd
	ASM_ADD_HIGH = _AsmAddHigh
	VEX_ADD_HIGH = _VexAddHigh
	ASM_SHUFFLE  = _AsmShuffle
	VEX_SHUFFLE  = _VexShuffle
	ASM_XOR      = _AsmXor
	VEX_XOR      = _VexXor
	ASM_AFFINE   = _AsmAffine
	VEX_AFFINE   = _VexAffine
	VEX_AFFINE_H = _VexAffineHigh
	VEX_MUL      = _VexMul
)
