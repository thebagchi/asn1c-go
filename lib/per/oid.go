package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// ErrObjectIdentifier is reported for contents octets that are not the encoding
// of an OBJECT IDENTIFIER or a RELATIVE-OID (X.690 clauses 8.19 and 8.20).
var (
	ErrObjectIdentifier = errors.New("malformed object identifier contents")
)

// X.690 clause 8.19: the base-128 subidentifiers of an OBJECT IDENTIFIER, which
// clause 8.20 reuses for a RELATIVE-OID.
//
// OID_STACK_OCTETS is the size of the array the encoders write contents octets
// into. A value that needs more octets grows into the heap.
const (
	OID_STACK_OCTETS    = 64
	SUBID_VALUE_BITS    = 7    // 8.19.2, bits 7 to 1 carry the value
	SUBID_VALUE_MASK    = 0x7F // 8.19.2
	SUBID_MORE_FLAG     = 0x80 // 8.19.2, bit 8 is set on every octet but the last
	SUBID_PADDING       = 0x80 // 8.19.2, the first octet is never 0x80
	OID_FIRST_ARC_UNIT  = 40   // 8.19.4, the first subidentifier is 40*X + Y
	OID_FIRST_ARC_MAX   = 2    // X.660, the first arc is 0, 1 or 2
	OID_FIRST_ARC_LIMIT = 40   // X.660, the second arc is below 40 under 0 and 1
	OID_MIN_ARCS        = 2    // X.680 32.3, an OBJECT IDENTIFIER has two arcs or more
)

// EncodeObjectIdentifier encodes an OBJECT IDENTIFIER, per X.691 clause 24: the
// contents octets of its BER encoding (X.690 clause 8.19) behind a length
// determinant. The first two arcs make one subidentifier, 40*first+second. A
// value with fewer than two arcs, a first arc above 2, a second arc of 40 or more
// under the first arcs 0 and 1, or a negative arc has no encoding and gives an
// error that wraps ErrValueOutOfRange.
//
// Revisions:
//   - 2026-02-09 23:42: initial creation
//   - 2026-10-19 11:38: moved to oid.go. It writes the subidentifiers itself instead of
//     calling encoding/asn1.Marshal, which stopped at 31-bit arcs on decode and
//     allocated a DER copy. The contents go into a stack array of 64 octets
//     (review P4-3)
func (e *Encoder) EncodeObjectIdentifier(oid asn1.ObjectIdentifier) error {
	if len(oid) < OID_MIN_ARCS {
		return fmt.Errorf(
			"object identifier of %d arcs: %w",
			len(oid),
			ErrValueOutOfRange,
		)
	}

	first, second := oid[0], oid[1]
	if first < 0 || first > OID_FIRST_ARC_MAX || second < 0 ||
		(first < OID_FIRST_ARC_MAX && second >= OID_FIRST_ARC_LIMIT) {
		return fmt.Errorf(
			"object identifier starts with arcs %d and %d: %w",
			first,
			second,
			ErrValueOutOfRange,
		)
	}

	var stack [OID_STACK_OCTETS]byte

	var contents = _AppendSubidentifier(
		stack[:0],
		uint64(first)*OID_FIRST_ARC_UNIT+uint64(second),
	)

	contents, err := _AppendArcs(
		contents,
		oid[2:],
	)
	if err != nil {
		return err
	}

	return e.EncodeOctetString(
		contents,
		Unconstrained(),
	)
}

// DecodeObjectIdentifier reads an OBJECT IDENTIFIER, per X.691 clause 24. The
// first subidentifier gives two arcs (X.690 clause 8.19.4). An arc above
// math.MaxInt64 gives an error that wraps ErrValueOutOfRange. Contents that are
// empty, padded or cut short give ErrObjectIdentifier.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation. EncodeObjectIdentifier had no
//     counterpart, so an OID field decoded as a SEQUENCE OF INTEGER over the
//     same octets and failed on the first component
//   - 2026-10-19 11:38: moved to oid.go. It reads the subidentifiers itself instead of
//     calling encoding/asn1.Unmarshal, so an arc has the range of an int and a
//     malformed encoding is refused in the same way for every arc (review P4-3)
func (d *Decoder) DecodeObjectIdentifier() (asn1.ObjectIdentifier, error) {
	contents, err := d._DecodeContents()
	if err != nil {
		return nil, err
	}

	if len(contents) == 0 {
		return nil, fmt.Errorf(
			"no subidentifier: %w",
			ErrObjectIdentifier,
		)
	}

	// Each octet without the continuation flag ends a subidentifier, and the
	// first one makes two arcs.
	var oid = make(
		asn1.ObjectIdentifier,
		0,
		_CountSubidentifiers(contents)+1,
	)

	value, rest, err := _ReadSubidentifier(contents)
	if err != nil {
		return nil, err
	}

	var (
		first = min(
			value/OID_FIRST_ARC_UNIT,
			OID_FIRST_ARC_MAX,
		)
		second = value - first*OID_FIRST_ARC_UNIT
	)

	if second > math.MaxInt {
		return nil, fmt.Errorf(
			"second arc above the largest int: %w",
			ErrValueOutOfRange,
		)
	}

	oid = append(
		oid,
		int(first),
		int(second),
	)

	return _ReadArcs(
		oid,
		rest,
	)
}

// _AppendSubidentifier appends value as a subidentifier of X.690 clause 8.19.2:
// base 128, most significant group first, bit 8 set on every octet but the last,
// in the fewest octets.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, shared by OBJECT IDENTIFIER and RELATIVE-OID
//     (review P4)
func _AppendSubidentifier(
	dst []byte,
	value uint64,
) []byte {
	groups := max(
		(bits.Len64(value)+SUBID_VALUE_BITS-1)/SUBID_VALUE_BITS,
		1,
	)

	for i := groups - 1; i > 0; i-- {
		dst = append(
			dst,
			byte(value>>(i*SUBID_VALUE_BITS))&SUBID_VALUE_MASK|SUBID_MORE_FLAG,
		)
	}

	return append(
		dst,
		byte(value)&SUBID_VALUE_MASK,
	)
}

// _AppendArcs appends each arc as a subidentifier. A negative arc has no
// encoding (X.680 clause 32.3: an arc is a non-negative number).
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, shared by OBJECT IDENTIFIER and RELATIVE-OID
//     (review P4)
func _AppendArcs(
	dst []byte,
	arcs []int,
) ([]byte, error) {
	for index, arc := range arcs {
		if arc < 0 {
			return dst, fmt.Errorf(
				"negative arc at position %d: %w",
				index,
				ErrValueOutOfRange,
			)
		}

		dst = _AppendSubidentifier(
			dst,
			uint64(arc),
		)
	}

	return dst, nil
}

// _ReadSubidentifier reads one subidentifier from the front of contents and
// returns it with the octets that follow. The first octet is not 0x80, which
// would be padding (X.690 clause 8.19.2), and the last octet has bit 8 clear.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, shared by OBJECT IDENTIFIER and RELATIVE-OID
//     (review P4)
func _ReadSubidentifier(contents []byte) (uint64, []byte, error) {
	if len(contents) == 0 || contents[0] == SUBID_PADDING {
		return 0, nil, fmt.Errorf(
			"subidentifier is empty or padded: %w",
			ErrObjectIdentifier,
		)
	}

	var value uint64

	for i, octet := range contents {
		if value > math.MaxUint64>>SUBID_VALUE_BITS {
			return 0, nil, fmt.Errorf(
				"subidentifier above 64 bits: %w",
				ErrValueOutOfRange,
			)
		}

		value = value<<SUBID_VALUE_BITS | uint64(octet&SUBID_VALUE_MASK)

		if octet&SUBID_MORE_FLAG == 0 {
			return value, contents[i+1:], nil
		}
	}

	return 0, nil, fmt.Errorf(
		"subidentifier ends in the contents: %w",
		ErrObjectIdentifier,
	)
}

// _ReadArcs appends one arc for each subidentifier left in contents. An arc
// above math.MaxInt64 gives an error that wraps ErrValueOutOfRange.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, shared by OBJECT IDENTIFIER and RELATIVE-OID
//     (review P4)
func _ReadArcs(
	arcs []int,
	contents []byte,
) ([]int, error) {
	for len(contents) > 0 {
		value, rest, err := _ReadSubidentifier(contents)
		if err != nil {
			return nil, err
		}

		if value > math.MaxInt {
			return nil, fmt.Errorf(
				"arc above the largest int: %w",
				ErrValueOutOfRange,
			)
		}

		arcs = append(
			arcs,
			int(value),
		)
		contents = rest
	}

	return arcs, nil
}

// _CountSubidentifiers counts the octets that end a subidentifier, which are the
// ones with bit 8 clear (X.690 clause 8.19.2).
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, so the arcs fit one allocation (review P4)
func _CountSubidentifiers(contents []byte) int {
	count := 0

	for _, octet := range contents {
		if octet&SUBID_MORE_FLAG == 0 {
			count++
		}
	}

	return count
}

// _DecodeContents reads contents octets behind an unconstrained length
// determinant (X.691 clauses 24 to 27 with 11.9). A value in one fragment, which
// is every value below 16K, is a window onto the decoder's input when the read
// is octet-aligned: the caller must read it at once and not keep it. A value in
// several fragments is copied.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, so the four types that carry contents octets do not
//     copy them before they read them (review P4)
func (d *Decoder) _DecodeContents() ([]byte, error) {
	var data []byte

	for {
		length, more, err := d.DecodeLengthDeterminant(Unconstrained())
		if err != nil {
			return nil, err
		}

		if d.aligned && length > 0 {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}

		chunk, err := d.codec.ReadView(int(length))
		if err != nil {
			return nil, err
		}

		if data == nil && !more {
			return chunk, nil
		}

		data = append(
			data,
			chunk...,
		)

		if !more {
			return data, nil
		}
	}
}
