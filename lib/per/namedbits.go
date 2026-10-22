package per

import (
	"encoding/asn1"
	"fmt"
	"math/bits"
)

// OCTET_MASK has every bit of an octet set.
const (
	OCTET_MASK = 0xFF
)

// EncodeNamedBitString encodes a BIT STRING whose type has a NamedBitList
// (X.680 22.7), per X.691 16.2 and 16.3: trailing 0 bits are removed, or added up
// to the lower bound of the size constraint, so the transmitted length is the
// smallest one that carries the value and satisfies SIZE. A length above the
// upper bound of an extensible SIZE is sent outside the root, trimmed (16.6).
// The encoding of the transmitted bits is that of EncodeBitString.
//
// The trimmed value shares the octets of value. Only a value that needs 0 bits
// added above its own length allocates, once, for those octets.
//
// Revisions:
//   - 2026-10-19 13:41: initial creation
func (e *Encoder) EncodeNamedBitString(
	value *asn1.BitString,
	size *Constraint,
) error {
	if value == nil {
		return fmt.Errorf(
			"named bit string: %w",
			ErrNilValue,
		)
	}

	count := uint64(value.BitLength)
	if uint64(len(value.Bytes))*BITS_PER_BYTE < count {
		return fmt.Errorf(
			"%d bits in %d octets: %w",
			count,
			len(value.Bytes),
			ErrShortBitString,
		)
	}

	var (
		length = max(
			_TrimmedLength(
				value.Bytes,
				count,
			),
			size._SizeLower(),
		)

		transmitted = asn1.BitString{
			Bytes:     value.Bytes,
			BitLength: int(length),
		}
	)
	if length > count {
		transmitted.Bytes = _PadBits(
			value.Bytes,
			count,
			length,
		)
	}

	return e.EncodeBitString(
		&transmitted,
		size,
	)
}

// _PadBits returns a copy of the first count bits of data, with 0 bits added up
// to length. It is the one allocation of EncodeNamedBitString.
//
// Revisions:
//   - 2026-10-19 13:41: initial creation
func _PadBits(
	data []byte,
	count uint64,
	length uint64,
) []byte {
	padded := make(
		[]byte,
		(length+BITS_PER_BYTE-1)/BITS_PER_BYTE,
	)
	copy(
		padded,
		data[:(count+BITS_PER_BYTE-1)/BITS_PER_BYTE],
	)

	// Bits of the last octet above count are padding, not part of the value.
	whole := count / BITS_PER_BYTE
	if rest := count % BITS_PER_BYTE; rest != 0 {
		padded[whole] &^= OCTET_MASK >> rest
		whole++
	}

	clear(padded[whole:])

	return padded
}

// _TrimmedLength returns the position of the last 1 bit among the first count
// bits of data, plus one, or 0 when there is none.
//
// Revisions:
//   - 2026-10-19 13:41: initial creation
func _TrimmedLength(
	data []byte,
	count uint64,
) uint64 {
	octets := (count + BITS_PER_BYTE - 1) / BITS_PER_BYTE

	for index := octets; index > 0; index-- {
		octet := data[index-1]
		if index == octets && count%BITS_PER_BYTE != 0 {
			octet &^= OCTET_MASK >> (count % BITS_PER_BYTE)
		}

		if octet != 0 {
			return index*BITS_PER_BYTE - uint64(bits.TrailingZeros8(octet))
		}
	}

	return 0
}
