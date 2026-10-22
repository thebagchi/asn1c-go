package per

import (
	"encoding/hex"
)

// How much input the Go hexadecimal kernel handles per iteration: a byte when
// encoding, a pair of characters when decoding.
const (
	HEX_GO_ENCODE = 1
	HEX_GO_DECODE = HEX_PAIR
)

// The hexadecimal kernels, narrowest first with Go leading, and the one
// chosen; _HexKernels is what each architecture contributes.
var (
	HEX_GO = &_Kernel{
		name:        NAME_GO,
		have:        true,
		encodeBlock: HEX_GO_ENCODE,
		decodeBlock: HEX_GO_DECODE,
		encode:      _HexEncodeGo,
		decode:      _HexDecodeGo,
	}
	HEX_KERNELS = _HexKernels()
	HEX_KERNEL  = _Select(HEX_KERNELS)
)

// _HexEncodeGo renders every byte of src, through encoding/hex, and returns
// how many it consumed: all of them.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _HexEncodeGo(
	dst,
	src []byte,
) int {
	hex.Encode(
		dst,
		src,
	)

	return len(src)
}

// _HexDecodeGo parses pairs of characters, through encoding/hex, and returns
// how many characters it consumed: every pair up to the first that holds a
// character outside the alphabet, never a lone last character.
//
// The error encoding/hex reports is not returned. A kernel says how far it
// got, and the caller decodes the remainder again to learn why it stopped, so
// the message is encoding/hex's own either way.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _HexDecodeGo(
	dst,
	src []byte,
) int {
	pairs, err := hex.Decode(
		dst,
		src[:len(src)&^1],
	)
	if err != nil {
		return pairs * HEX_PAIR
	}

	return len(src) &^ 1
}
