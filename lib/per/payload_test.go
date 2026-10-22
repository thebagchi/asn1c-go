package per_test

// The sizes the text conversions are timed over, in bytes of binary data: 64
// is two hex-encode blocks and eight binary-encode ones, 4096 is where the
// per-byte work dominates.
var (
	TEXT_SIZES = []int{64, 4096}
)

// _TextPayload is a deterministic byte string with every byte value in it,
// shared by the hexadecimal and binary tests and benchmarks.
//
// Revisions:
//   - 2026-09-23 08:30: initial creation
func _TextPayload(size int) []byte {
	const STRIDE = 7

	data := make(
		[]byte,
		size,
	)
	for idx := range data {
		data[idx] = byte(idx*STRIDE + 1)
	}

	return data
}
