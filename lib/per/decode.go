package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// Sentinel errors reported while decoding.
var (
	ErrLengthTooLarge   = errors.New("length determinant is wider than a value holds")
	ErrLengthFragmented = errors.New("value cannot be fragmented but its length is")
	ErrFragmentCount    = errors.New("fragment multiplier is not between one and four")
)

// Decoder reads a PER encoding, in the variant it was created for.
type Decoder struct {
	codec   *bitbuffer.Codec
	aligned bool
}

// NewAlignedDecoder returns a Decoder for the ALIGNED variant, APER.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation as NewDecoder(data, aligned bool)
//   - 2026-09-22 06:43: split into one constructor per variant
func NewAlignedDecoder(data []byte) *Decoder {
	return &Decoder{
		codec:   bitbuffer.CreateReader(data),
		aligned: true,
	}
}

// NewUnalignedDecoder returns a Decoder for the UNALIGNED variant, UPER.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation as NewDecoder(data, aligned bool)
//   - 2026-09-22 06:43: split into one constructor per variant
func NewUnalignedDecoder(data []byte) *Decoder {
	return &Decoder{
		codec:   bitbuffer.CreateReader(data),
		aligned: false,
	}
}

// Aligned reports whether this Decoder reads the ALIGNED variant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) Aligned() bool {
	return d.aligned
}

// DecodeConstrainedWholeNumber reads the field X.691 clause 11.5 selects from
// the range, which is ub - lb + 1.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: derives the ALIGNED bit-field width from the range
//     rather than from a table of eight cases, whose fall-through left the width
//     at zero for a range it did not list
//   - 2026-10-19 11:14: works on the span ub - lb as a uint64, so the widest ranges no longer
//     wrap, and refuses an offset above the span, which no value has (review
//     P3-2, P3-4)
//   - 2026-10-19 11:38: the field selection moved to _DecodeOffset, which DecodeUnsigned
//     shares (review P4)
func (d *Decoder) DecodeConstrainedWholeNumber(
	lb,
	ub int64,
) (int64, error) {
	offset, err := d._DecodeOffset(uint64(ub) - uint64(lb))
	if err != nil {
		return 0, err
	}

	return int64(uint64(lb) + offset), nil
}

// DecodeNormallySmallNonNegativeWholeNumber reads a number encoded per X.691
// clause 11.6.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-10-20 01:13: reads the octets itself, so an offset above int64 stays
//     valid (review P11-2)
func (d *Decoder) DecodeNormallySmallNonNegativeWholeNumber() (uint64, error) {
	bit, err := d.codec.Read(1)
	if err != nil {
		return 0, err
	}

	if bit == 0 {
		return d.codec.Read(NORMALLY_SMALL_BITS)
	}

	value, _, err := d._ReadOctetAligned()

	return value, err
}

// DecodeSemiConstrainedWholeNumber reads a number encoded per X.691 clause 11.7
// as an offset from lb. An offset that moves the value past int64 is an error.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: returns int64 rather than uint64, since the value it
//     reconstructs is lb plus an offset and lb may be negative
//   - 2026-10-20 01:13: returns ErrValueOutOfRange when lb plus the offset
//     does not fit in int64 (review P11-2)
func (d *Decoder) DecodeSemiConstrainedWholeNumber(lb int64) (int64, error) {
	raw, _, err := d._ReadOctetAligned()
	if err != nil {
		return 0, err
	}

	// The room above lb is computed in uint64, where a negative lb wraps to
	// the right distance.
	room := uint64(math.MaxInt64) - uint64(lb)

	if raw > room {
		return 0, fmt.Errorf(
			"offset %d from %d: %w",
			raw,
			lb,
			ErrValueOutOfRange,
		)
	}

	return int64(uint64(lb) + raw), nil
}

// DecodeUnconstrainedWholeNumber reads a number encoded per X.691 clause 11.8 in
// two's complement.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: rejects a length above eight octets. It multiplied the
//     octet count by eight into a uint8, so a length of 32 asked for zero bits
//     and returned zero and no error, while 33 consumed one octet and left the
//     stream pointing into the middle of a value
func (d *Decoder) DecodeUnconstrainedWholeNumber() (int64, error) {
	raw, width, err := d._ReadOctetAligned()
	if err != nil {
		return 0, err
	}

	return _SignExtend(
		raw,
		width,
	), nil
}

// DecodeLengthDeterminant reads a length, per X.691 clause 11.9, and reports
// whether another fragment follows.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: takes a Constraint, whose lower bound for a length is
//     zero when the type states none
func (d *Decoder) DecodeLengthDeterminant(size *Constraint) (uint64, bool, error) {
	upper, bounded := size._SizeUpper()
	if !bounded || upper >= MAX_CONSTRAINED_LENGTH {
		return d.DecodeUnconstrainedLength()
	}

	var (
		lower = size._SizeLower()

		value, err = d.DecodeConstrainedWholeNumber(
			int64(lower),
			int64(upper),
		)
	)
	if err != nil {
		return 0, false, err
	}

	return uint64(value), false, nil
}

// DecodeUnconstrainedLength reads a length with no upper bound, per X.691
// clauses 11.9.3.6 to 11.9.3.8.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeUnconstrainedLength() (uint64, bool, error) {
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, false, err
		}
	}

	first, err := d.codec.Read(BITS_PER_BYTE)
	if err != nil {
		return 0, false, err
	}

	if first&LENGTH_MSB_FLAG == 0 {
		return first, false, nil
	}

	if first&LENGTH_FORM_MASK == LENGTH_LONG_FORM {
		second, err := d.codec.Read(BITS_PER_BYTE)
		if err != nil {
			return 0, false, err
		}

		return (first&LENGTH_SIX_BIT_MASK)<<BITS_PER_BYTE | second, false, nil
	}

	// Clause 11.9.3.8 restricts the multiplier to one through four, so that an
	// implementation never has to hold more than 64K at once.
	multiple := first & LENGTH_SIX_BIT_MASK
	if multiple < FRAGMENT_MULTIPLIER_MIN || multiple > FRAGMENT_MULTIPLIER_MAX {
		return 0, false, fmt.Errorf(
			"multiplier %d: %w",
			multiple,
			ErrFragmentCount,
		)
	}

	return multiple * FRAGMENT_SIZE, true, nil
}

// DecodeNormallySmallLength reads the length of an extension bitmap, per X.691
// clause 11.9.3.4.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeNormallySmallLength() (uint64, bool, error) {
	bit, err := d.codec.Read(1)
	if err != nil {
		return 0, false, err
	}

	if bit != 0 {
		return d.DecodeUnconstrainedLength()
	}

	value, err := d.codec.Read(NORMALLY_SMALL_BITS)
	if err != nil {
		return 0, false, err
	}

	return value + 1, false, nil
}

// DecodeBoolean reads a boolean from one bit, per X.691 clause 12.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeBoolean() (bool, error) {
	bit, err := d.codec.Read(1)
	if err != nil {
		return false, err
	}

	return bit != 0, nil
}

// ReadExtensionBit reads the bit that says whether what follows lies outside the
// extension root, the counterpart of Encoder.WriteExtensionBit.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
func (d *Decoder) ReadExtensionBit() (bool, error) {
	return d.DecodeBoolean()
}

// DecodeInteger reads an integer under its constraint, per X.691 clause 13.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeInteger(size *Constraint) (int64, error) {
	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return 0, err
		}

		if outside {
			return d.DecodeUnconstrainedWholeNumber()
		}

		size = size._Root()
	}

	var (
		lower, hasLower = size.Lower()
		upper, hasUpper = size.Upper()
	)

	switch {
	case hasLower && hasUpper:
		return d.DecodeConstrainedWholeNumber(
			lower,
			upper,
		)
	case hasLower:
		return d.DecodeSemiConstrainedWholeNumber(lower)
	default:
		return d.DecodeUnconstrainedWholeNumber()
	}
}

// DecodeEnumerated reads an enumeration index, per X.691 clause 14. root gives
// the indices of the extension root and carries the extension marker.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: takes the root as a Constraint rather than a count and
//     a flag
func (d *Decoder) DecodeEnumerated(root *Constraint) (uint64, error) {
	upper, bounded := root.Upper()
	if !bounded || upper < 0 {
		return 0, ErrEnumNoCount
	}

	if root.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return 0, err
		}

		if outside {
			return d._DecodeAddedEnum(uint64(upper) + 1)
		}
	}

	value, err := d.DecodeConstrainedWholeNumber(
		0,
		upper,
	)
	if err != nil {
		return 0, err
	}

	return uint64(value), nil
}

// DecodeReal reads a real, per X.691 clause 15.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: reports a malformed encoding instead of returning zero
//     and no error, and reads the decimal form of X.690 clause 8.5.8 rather than
//     parsing its ASCII digits as though they were a binary exponent
func (d *Decoder) DecodeReal() (float64, error) {
	contents, err := d.DecodeOctetString(Unconstrained())
	if err != nil {
		return 0, err
	}

	return _ParseReal(contents)
}

// ReadBits reads count bits into a byte slice, the leading bit first.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: fills one slice of the final size instead of appending
//     through a bytes.Buffer
func (d *Decoder) ReadBits(count uint64) ([]byte, error) {
	if count == 0 {
		return []byte{}, nil
	}

	var (
		whole = count / BITS_PER_BYTE
		rest  = count % BITS_PER_BYTE
		data  = make(
			[]byte,
			0,
			(count+BITS_PER_BYTE-1)/BITS_PER_BYTE,
		)
	)

	if whole > 0 {
		chunk, err := d.codec.ReadBytes(int(whole))
		if err != nil {
			return nil, err
		}

		data = append(
			data,
			chunk...,
		)
	}

	if rest == 0 {
		return data, nil
	}

	value, err := d.codec.Read(uint8(rest))
	if err != nil {
		return nil, err
	}

	return append(
		data,
		byte(value<<(BITS_PER_BYTE-rest)),
	), nil
}

// DecodeBitString reads a bit string under its size constraint, per X.691
// clause 16.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeBitString(size *Constraint) (*asn1.BitString, error) {
	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return nil, err
		}

		if outside {
			return d._DecodeBitFragments(_Unbounded())
		}

		size = size._Root()
	}

	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return d._DecodeBitFragments(size)
	}

	if fixed == 0 {
		return new(asn1.BitString), nil
	}

	if d.aligned && fixed > BITSTRING_DIRECT_MAX_BITS {
		if err := d.codec.Advance(); err != nil {
			return nil, err
		}
	}

	data, err := d.ReadBits(fixed)
	if err != nil {
		return nil, err
	}

	return &asn1.BitString{
		Bytes:     data,
		BitLength: int(fixed),
	}, nil
}

// DecodeOctetString reads an octet string under its size constraint, per X.691
// clause 17.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: returns what ReadBytes allocated rather than copying it
//     into a second slice of the same size
func (d *Decoder) DecodeOctetString(size *Constraint) ([]byte, error) {
	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return nil, err
		}

		if outside {
			return d._DecodeOctetFragments(_Unbounded())
		}

		size = size._Root()
	}

	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return d._DecodeOctetFragments(size)
	}

	if fixed == 0 {
		return []byte{}, nil
	}

	if d.aligned && fixed > OCTET_STRING_DIRECT_MAX {
		if err := d.codec.Advance(); err != nil {
			return nil, err
		}
	}

	return d.codec.ReadBytes(int(fixed))
}

// DecodeNull reads a NULL, per X.691 clause 18, which reads nothing.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeNull() error {
	return nil
}

// DecodeChoiceId reads the index of a root CHOICE alternative, per X.691
// clauses 23.6 and 23.7.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes the root as a Constraint, and the extension case
//     moved to DecodeChoiceExtensionId
func (d *Decoder) DecodeChoiceId(root *Constraint) (int64, error) {
	var (
		lower, _ = root.Lower()
		upper, _ = root.Upper()
	)

	return d.DecodeConstrainedWholeNumber(
		lower,
		upper,
	)
}

// DecodeChoiceExtensionId reads the index of an extension CHOICE alternative,
// per X.691 clause 23.8.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split from DecodeChoiceId
func (d *Decoder) DecodeChoiceExtensionId() (int64, error) {
	value, err := d.DecodeNormallySmallNonNegativeWholeNumber()

	return int64(value), err
}

// _DecodeOffset reads the field X.691 clause 11.5 selects from a range of
// span + 1 values and returns the offset from the lower bound.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, the body of DecodeConstrainedWholeNumber, so that
//     INTEGER above int64 uses the same clause 11.5 logic (review P4)
func (d *Decoder) _DecodeOffset(span uint64) (uint64, error) {
	// Clause 11.5.4: a range of one carries no bits at all.
	if span == 0 {
		return 0, nil
	}

	if !d.aligned || span < RANGE_BITFIELD_MAX {
		width := BitsNonNegativeBinaryInteger(span)

		return d._ReadOffset(
			span,
			uint8(width),
		)
	}

	if span < RANGE_TWO_OCTET_MAX {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}

		width := uint8(BITS_PER_BYTE)
		if span >= RANGE_ONE_OCTET {
			width = DOUBLE_OCTET_BITS
		}

		return d._ReadOffset(
			span,
			width,
		)
	}

	return d._DecodeIndefinite(span)
}

// _ReadOffset reads width bits as an offset from the lower bound. The offset is
// at most span, the difference of the bounds; a field can hold more, and a
// larger offset names no value of the type (X.691 clauses 13.2, 14).
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of
//     DecodeConstrainedWholeNumber
//   - 2026-10-19 11:14: takes the span and refuses an offset above it (review P3-4)
//   - 2026-10-19 11:38: returns the offset and leaves the addition of the lower bound to the
//     caller, which is int64 for one and uint64 for the other (review P4)
func (d *Decoder) _ReadOffset(
	span uint64,
	width uint8,
) (uint64, error) {
	value, err := d.codec.Read(width)
	if err != nil {
		return 0, err
	}

	if value > span {
		return 0, fmt.Errorf(
			"offset %d above the span %d: %w",
			value,
			span,
			ErrValueOutOfRange,
		)
	}

	return value, nil
}

// _ReadOctetAligned reads a length determinant and the octets it counts, which
// is the shape clauses 11.7.4 and 11.8.3 share. It returns the raw octets as a
// number, and how many there were.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, shared by the semi-constrained and
//     unconstrained whole number decoders, each of which turned an octet count
//     into a bit count without checking that it fitted
func (d *Decoder) _ReadOctetAligned() (uint64, int, error) {
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, 0, err
		}
	}

	octets, more, err := d.DecodeLengthDeterminant(Unconstrained())
	if err != nil {
		return 0, 0, err
	}

	if more {
		return 0, 0, fmt.Errorf(
			"integer: %w",
			ErrLengthFragmented,
		)
	}

	if octets == 0 || octets > MAX_VALUE_OCTETS {
		return 0, 0, fmt.Errorf(
			"%d octets: %w",
			octets,
			ErrLengthTooLarge,
		)
	}

	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, 0, err
		}
	}

	value, err := d.codec.Read(uint8(octets * BITS_PER_BYTE))
	if err != nil {
		return 0, 0, err
	}

	return value, int(octets), nil
}

// _DecodeIndefinite reads the indefinite length case of X.691 clause 11.5.7.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of
//     DecodeConstrainedWholeNumber
//   - 2026-10-19 11:14: passes the span to _ReadOffset (review P3-4)
//   - 2026-10-19 11:38: returns the offset, not the value (review P4)
func (d *Decoder) _DecodeIndefinite(span uint64) (uint64, error) {
	var (
		bounds = Constrained(
			1,
			int64(OctetsNonNegativeBinaryIntegerLength(span)),
		)

		octets, _, err = d.DecodeLengthDeterminant(bounds)
	)
	if err != nil {
		return 0, err
	}

	if octets == 0 || octets > MAX_VALUE_OCTETS {
		return 0, fmt.Errorf(
			"%d octets: %w",
			octets,
			ErrLengthTooLarge,
		)
	}

	if err := d.codec.Advance(); err != nil {
		return 0, err
	}

	return d._ReadOffset(
		span,
		uint8(octets*BITS_PER_BYTE),
	)
}

// _DecodeBitFragments reads a bit string behind a length determinant, following
// the fragments of clause 11.9.3.8.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation as DecodeBitStringFragments
//   - 2026-10-19 11:14: refuses a total length outside the size constraint (review P3-1)
func (d *Decoder) _DecodeBitFragments(size *Constraint) (*asn1.BitString, error) {
	if err := d._AlignForLength(size); err != nil {
		return nil, err
	}

	var (
		data  []byte
		count uint64
	)

	for {
		length, more, err := d.DecodeLengthDeterminant(size)
		if err != nil {
			return nil, err
		}

		if err := size._CheckUpper(count + length); err != nil {
			return nil, err
		}

		if d.aligned && length > 0 {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}

		chunk, err := d.ReadBits(length)
		if err != nil {
			return nil, err
		}

		data = append(
			data,
			chunk...,
		)
		count = count + length

		if !more {
			if err := size._CheckLength(count); err != nil {
				return nil, err
			}

			return &asn1.BitString{
				Bytes:     data,
				BitLength: int(count),
			}, nil
		}
	}
}

// _DecodeOctetFragments reads an octet string behind a length determinant,
// following the fragments of clause 11.9.3.8.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation as DecodeOctetStringFragments
//   - 2026-09-22 06:43: returns the one fragment directly when there is only
//     one, which is every value below 16K, instead of copying it through a
//     bytes.Buffer
//   - 2026-10-19 11:14: refuses a total length outside the size constraint (review P3-1)
func (d *Decoder) _DecodeOctetFragments(size *Constraint) ([]byte, error) {
	if err := d._AlignForLength(size); err != nil {
		return nil, err
	}

	var (
		data  []byte
		total uint64
	)

	for {
		length, more, err := d.DecodeLengthDeterminant(size)
		if err != nil {
			return nil, err
		}

		total = total + length
		if err := size._CheckUpper(total); err != nil {
			return nil, err
		}

		if d.aligned && length > 0 {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}

		chunk, err := d.codec.ReadBytes(int(length))
		if err != nil {
			return nil, err
		}

		if data == nil && !more {
			return chunk, size._CheckLength(total)
		}

		data = append(
			data,
			chunk...,
		)

		if !more {
			return data, size._CheckLength(total)
		}
	}
}

// _AlignForLength advances before a length determinant that is not a constrained
// whole number, the counterpart of Encoder._AlignForLength.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _AlignForLength(size *Constraint) error {
	if !d.aligned {
		return nil
	}

	if upper, bounded := size._SizeUpper(); bounded && upper < MAX_CONSTRAINED_LENGTH {
		return nil
	}

	return d.codec.Advance()
}

// _DecodeAddedEnum reads an enumerator added after the extension marker, whose
// index clause 14.3 restarts from zero and offsets by the size of the root.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeEnumerated
func (d *Decoder) _DecodeAddedEnum(count uint64) (uint64, error) {
	value, err := d.DecodeNormallySmallNonNegativeWholeNumber()
	if err != nil {
		return 0, err
	}

	return value + count, nil
}
