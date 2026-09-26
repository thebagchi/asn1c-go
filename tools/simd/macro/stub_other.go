//go:build !amd64

package macro

// _ShiftBlocks is the pure-Go stand-in for the assembly kernel, so the package
// builds and its tests run on an architecture that has no kernel yet.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation
func _ShiftBlocks(dst, src []byte, free, used uint8) {
	for i := range dst {
		dst[i] = src[i]<<free | src[i+1]>>used
	}
}
