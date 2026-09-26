//go:build !amd64

package per

// _HexKernels lists the one kernel an architecture without assembly has.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _HexKernels() []*_Kernel {
	return []*_Kernel{HEX_GO}
}

// _EncodeHex has no assembly kernel to run here: it takes nothing, and the Go
// kernel the caller finishes with renders everything.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 02:00: takes nothing; the Go kernel moved to the caller
func _EncodeHex(dst, src []byte) int {
	return 0
}

// _DecodeHex has no assembly kernel to run here: it takes nothing, and the Go
// kernel the caller finishes with parses everything.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 02:00: takes nothing; the Go kernel moved to the caller
func _DecodeHex(dst, src []byte) int {
	return 0
}
