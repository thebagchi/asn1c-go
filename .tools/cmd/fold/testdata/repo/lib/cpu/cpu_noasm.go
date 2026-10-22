//go:build !amd64

package cpu

// On an architecture with no kernels, every answer is no. These are constants
// rather than variables so that a caller reads the same name on every
// architecture and the compiler can drop the branches they guard.
const (
	HAS_SSE2   = false
	HAS_AVX2   = false
	HAS_AVX512 = false
	HAS_GFNI   = false
)
