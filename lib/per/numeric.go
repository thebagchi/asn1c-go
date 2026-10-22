package per

// The NumericString alphabet as the Go kernel spells it: a space is index 0
// and the digits are 1..10, per clause 30.4.4's renumbering of " 0123456789".
const (
	NUMERIC_SPACE       = ' '
	NUMERIC_FIRST_DIGIT = '0'
	NUMERIC_LAST_DIGIT  = '9'
	NUMERIC_LAST_INDEX  = 10
	NUMERIC_GO_ENCODE   = NUMERIC_PAIR
	NUMERIC_GO_DECODE   = 1
)

// The NumericString kernels, narrowest first with Go leading, and the one
// chosen; _NumericKernels is what each architecture contributes.
var (
	NUMERIC_GO = &_Kernel{
		name:        NAME_GO,
		have:        true,
		encodeBlock: NUMERIC_GO_ENCODE,
		decodeBlock: NUMERIC_GO_DECODE,
		encode:      _PackNumericGo,
		decode:      _UnpackNumericGo,
	}
	NUMERIC_KERNELS = _NumericKernels()
	NUMERIC_KERNEL  = _Select(NUMERIC_KERNELS)
)

// _PackNumericGo packs pairs of characters into nibbles, a pair at a time, and
// returns how many characters it consumed: every pair up to the first that
// holds a character outside the alphabet, never a lone last character.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _PackNumericGo(
	dst,
	src []byte,
) int {
	for idx := 0; idx+NUMERIC_PAIR <= len(src); idx += NUMERIC_PAIR {
		high, ok := _NumericValue(src[idx])
		if !ok {
			return idx
		}

		low, ok := _NumericValue(src[idx+1])
		if !ok {
			return idx
		}

		dst[idx/NUMERIC_PAIR] = high<<NUMERIC_BITS | low
	}

	return len(src) &^ 1
}

// _UnpackNumericGo unpacks nibbles into characters, a byte at a time, and
// returns how many bytes it consumed: every byte up to the first that holds a
// nibble outside the alphabet.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _UnpackNumericGo(
	dst,
	src []byte,
) int {
	for idx, pair := range src {
		var (
			high = pair >> NUMERIC_BITS
			low  = pair & NUMERIC_NIBBLE
		)

		if high > NUMERIC_LAST_INDEX || low > NUMERIC_LAST_INDEX {
			return idx
		}

		dst[idx*NUMERIC_PAIR] = _NumericChar(high)
		dst[idx*NUMERIC_PAIR+1] = _NumericChar(low)
	}

	return len(src)
}

// _NumericValue returns a character's index in the alphabet.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _NumericValue(char byte) (byte, bool) {
	switch {
	case char == NUMERIC_SPACE:
		return 0, true
	case char >= NUMERIC_FIRST_DIGIT && char <= NUMERIC_LAST_DIGIT:
		return char - NUMERIC_FIRST_DIGIT + 1, true
	default:
		return 0, false
	}
}

// _NumericChar returns the character an index stands for; the index must be
// in the alphabet.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _NumericChar(index byte) byte {
	if index == 0 {
		return NUMERIC_SPACE
	}

	return NUMERIC_FIRST_DIGIT + index - 1
}
