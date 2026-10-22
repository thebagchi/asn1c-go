package per

import (
	"encoding/binary"
)

// How much input the Go binary-text kernel handles per iteration: a byte when
// encoding, a word of eight characters when decoding.
const (
	BIN_GO_ENCODE = 1
	BIN_GO_DECODE = BITS_PER_BYTE
)

// The binary-text kernels, narrowest first with Go leading, and the one
// chosen; _BinKernels is what each architecture contributes.
var (
	BIN_GO = &_Kernel{
		name:        NAME_GO,
		have:        true,
		encodeBlock: BIN_GO_ENCODE,
		decodeBlock: BIN_GO_DECODE,
		encode:      _BinaryEncodeGo,
		decode:      _BinaryDecodeGo,
	}
	BIN_KERNELS = _BinKernels()
	BIN_KERNEL  = _Select(BIN_KERNELS)
)

// _BinaryEncodeGo renders every byte of src as eight characters, a word at a
// time, and returns how many bytes it consumed: all of them.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation, the word loop of BitStringToBinary
//     as a kernel in the table
func _BinaryEncodeGo(
	dst,
	src []byte,
) int {
	for idx, value := range src {
		lanes := _SpreadBits(value)
		binary.BigEndian.PutUint64(
			dst[idx*BITS_PER_BYTE:],
			lanes|ASCII_ZERO_LANES,
		)
	}

	return len(src)
}

// _BinaryDecodeGo parses characters eight at a time and returns how many it
// consumed: every word up to the first that holds a character which is
// neither '0' nor '1', never a partial last word.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation, the word loop of BitStringFromBinary
//     as a kernel in the table
func _BinaryDecodeGo(
	dst,
	src []byte,
) int {
	pos := 0

	for ; pos+BITS_PER_BYTE <= len(src); pos += BITS_PER_BYTE {
		bits, ok := _BinaryWord(binary.BigEndian.Uint64(src[pos:]))
		if !ok {
			return pos
		}

		dst[pos/BITS_PER_BYTE] = bits
	}

	return pos
}
