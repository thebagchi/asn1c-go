//go:build !amd64

package per

// SEPTET_KERNELS says that this architecture has no septet kernels, so the decoder reads
// its characters one word at a time.
const (
	SEPTET_KERNELS = false
)

// _PackSeptetKernels has no assembly kernel to run here: it takes nothing, and the shift of
// the caller packs everything.
//
// Revisions:
//   - 2026-10-21 22:05: initial creation (review P32)
func _PackSeptetKernels(
	dst,
	text []byte,
) int {
	return 0
}

// _SpreadSeptetKernels has no assembly kernel to run here: it writes nothing.
//
// Revisions:
//   - 2026-10-21 22:05: initial creation (review P32)
func _SpreadSeptetKernels(
	dst,
	src []byte,
) int {
	return 0
}
