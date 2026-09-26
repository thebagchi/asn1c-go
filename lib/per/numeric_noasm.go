//go:build !amd64

package per

// _NumericKernels lists the one kernel an architecture without assembly has.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _NumericKernels() []*_Kernel {
	return []*_Kernel{NUMERIC_GO}
}

// _PackNumeric has no assembly kernel to run here: it takes nothing, and the Go
// kernel the caller finishes with packs everything.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 02:00: takes nothing; the Go kernel moved to the caller
func _PackNumeric(dst, src []byte) int {
	return 0
}

// _UnpackNumeric has no assembly kernel to run here: it takes nothing, and the Go
// kernel the caller finishes with unpacks everything.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 02:00: takes nothing; the Go kernel moved to the caller
func _UnpackNumeric(dst, src []byte) int {
	return 0
}
