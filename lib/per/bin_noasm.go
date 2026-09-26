//go:build !amd64

package per

// _BinKernels lists the one kernel an architecture without assembly has.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _BinKernels() []*_Kernel {
	return []*_Kernel{BIN_GO}
}

// _EncodeBinary has no assembly kernel to run here: it takes nothing, and the Go
// kernel the caller finishes with renders everything.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 02:00: takes nothing; the Go kernel moved to the caller
func _EncodeBinary(dst, src []byte) int {
	return 0
}

// _DecodeBinary has no assembly kernel to run here: it takes nothing, and the Go
// kernel the caller finishes with parses everything.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 02:00: takes nothing; the Go kernel moved to the caller
func _DecodeBinary(dst, src []byte) int {
	return 0
}
