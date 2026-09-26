//go:build !amd64

package macro

// The macros in vex_amd64.h encode x86 instructions, so there is nothing to run
// here. The constants stay declared so a test can refer to them on any
// architecture and skip.
const (
	VECTOR_BYTES    = 32
	MATRIX_BYTES    = 8
	BITS_PER_MATRIX = 8
)
