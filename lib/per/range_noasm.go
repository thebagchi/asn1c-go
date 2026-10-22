//go:build !amd64

package per

// RANGE_KERNEL_MIN is the shortest text _OutsideRange hands to the kernels. There are no
// kernels here, so the value only keeps the caller the same on every architecture.
const (
	RANGE_KERNEL_MIN = 32
)

// _CheckRangeKernels has no assembly kernel to run here: it checks nothing, and the
// word check of the caller checks everything.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
func _CheckRangeKernels(
	text []byte,
	lower,
	upper byte,
) int {
	return 0
}
