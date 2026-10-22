package per

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

// The two characters of the text form of a bit string.
const (
	BINARY_ZERO = '0'
	BINARY_ONE  = '1'
)

// ParseBitString converts text of the characters '0' and '1' to a bit string.
// Character i is bit i: the first character is the high bit of the first octet,
// the order of asn1.BitString and of this codec. The unused low bits of the last
// octet are 0.
//
// Eight characters become one octet: the assembly kernels take whole blocks, the
// Go kernel the words after them, and the tail is padded with '0', which is also
// the zero bit PER pads with. One allocation holds the octets. A character that
// is neither '0' nor '1' returns the zero value and an error that names its
// index; a space is such a character.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation, as BitStringFromBinary in types.go
//   - 2026-09-22 06:43: validates and gathers eight characters at a time
//   - 2026-09-23 08:40: the vector kernel takes whole blocks and the word loop
//     the remainder
//   - 2026-10-21 21:36: ParseBitString in bitstring.go; returns the value, and an
//     error names the index of the bad character (review P31)
func ParseBitString(text string) (asn1.BitString, error) {
	if text == "" {
		return asn1.BitString{}, nil
	}

	var (
		src  = _StringBytes(text)
		data = make(
			[]byte,
			(len(src)+BITS_PER_BYTE-1)/BITS_PER_BYTE,
		)
		pos = _DecodeBinary(
			data,
			src,
		)
	)

	pos += _BinaryDecodeGo(
		data[pos/BITS_PER_BYTE:],
		src[pos:],
	)

	// The word loop stops before a word that holds a bad character, so whatever is
	// left - a whole bad word or a short tail - is at most eight characters at pos.
	if pos < len(src) && !_ParseTail(
		data,
		src,
		pos,
	) {
		return asn1.BitString{}, fmt.Errorf(
			"at index %d: %w",
			_BadIndex(
				src,
				pos,
			),
			ErrInvalidBinary,
		)
	}

	return asn1.BitString{
		Bytes:     data,
		BitLength: len(src),
	}, nil
}

// FormatBitString converts a bit string to its text of '0' and '1', bit 0 first.
// It prints BitLength characters and no pad bits.
//
// Eight characters come from each octet: the assembly kernels take whole blocks
// of whole octets, and the Go kernel the rest. One allocation holds the text,
// and it becomes the string with no copy.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation, as BitStringToBinary in types.go
//   - 2026-09-22 06:43: builds the result in one allocation
//   - 2026-09-23 08:40: the vector kernel takes whole blocks of whole bytes and
//     the word loop the rest
//   - 2026-10-21 21:36: FormatBitString in bitstring.go; a nil value, a negative
//     length or a short octet slice is an error, where the length was clamped
//     (review P31)
func FormatBitString(value *asn1.BitString) (string, error) {
	if err := _CheckBitString(value); err != nil {
		return "", err
	}

	if value.BitLength == 0 {
		return "", nil
	}

	var (
		length = value.BitLength
		octets = (length + BITS_PER_BYTE - 1) / BITS_PER_BYTE
		text   = make(
			[]byte,
			octets*BITS_PER_BYTE,
		)
		done = _EncodeBinary(
			text,
			value.Bytes[:length/BITS_PER_BYTE],
		)
	)

	_BinaryEncodeGo(
		text[done*BITS_PER_BYTE:],
		value.Bytes[done:octets],
	)

	return _BytesString(text[:length]), nil
}

// _CheckBitString refuses a bit string that FormatBitString cannot print: nil, a
// negative length, or fewer octets than the length needs.
//
// Revisions:
//   - 2026-10-21 21:36: initial creation (review P31)
func _CheckBitString(value *asn1.BitString) error {
	if value == nil {
		return fmt.Errorf(
			"bit string: %w",
			ErrNilValue,
		)
	}

	if value.BitLength < 0 {
		return fmt.Errorf(
			"bit string length %d: %w",
			value.BitLength,
			ErrValueOutOfRange,
		)
	}

	need := (value.BitLength + BITS_PER_BYTE - 1) / BITS_PER_BYTE
	if len(value.Bytes) < need {
		return fmt.Errorf(
			"%d bits in %d octets: %w",
			value.BitLength,
			len(value.Bytes),
			ErrShortBitString,
		)
	}

	return nil
}

// _ParseTail parses the at most eight characters of src from pos into the octet
// at pos/8, padded with '0', and reports whether every one is '0' or '1'. Copying
// the padding constant beats filling it: Go turns a zero fill into a memclr but
// leaves a non-zero one as a loop.
//
// Revisions:
//   - 2026-10-19 10:38: initial creation, as _DecodeBinaryTail in types.go
//   - 2026-10-21 21:36: reports a bad character instead of making the error, so
//     the caller names its index (review P31)
func _ParseTail(
	data,
	src []byte,
	pos int,
) bool {
	tail := ASCII_ZEROS
	copy(
		tail[:],
		src[pos:],
	)

	bits, ok := _BinaryWord(binary.BigEndian.Uint64(tail[:]))
	if !ok {
		return false
	}

	data[pos/BITS_PER_BYTE] = bits

	return true
}

// _BadIndex returns the index of the first character of src from pos that is
// neither '0' nor '1'. The caller knows that one is there.
//
// Revisions:
//   - 2026-10-21 21:36: initial creation (review P31)
func _BadIndex(
	src []byte,
	pos int,
) int {
	for src[pos] == BINARY_ZERO || src[pos] == BINARY_ONE {
		pos++
	}

	return pos
}
