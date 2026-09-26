//go:build !amd64

package bitbuffer

// _ShiftKernels lists the one kernel an architecture without assembly has.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _ShiftKernels() []*_Kernel {
	return []*_Kernel{SHIFT_GO}
}

// _RunShift runs the only kernel there is.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _RunShift(dst, src []byte, left, right uint8) {
	_ShiftBlocksGo(dst, src, left, right)
}
