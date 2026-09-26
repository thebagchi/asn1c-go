package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// Sentinel errors reported while decoding.
var (
	ErrLengthTooLarge   = errors.New("length determinant is wider than a value holds")
	ErrLengthFragmented = errors.New("value cannot be fragmented but its length is")
	ErrFragmentCount    = errors.New("fragment multiplier is not between one and four")
	ErrNotPointer       = errors.New("target is not a non-nil pointer")
	ErrChoiceIndex      = errors.New("choice index has no alternative")
	ErrOpenTypeNil      = errors.New("open type has no concrete value to decode into")
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
func (d *Decoder) DecodeConstrainedWholeNumber(lb, ub int64) (int64, error) {
	span := ub - lb + 1

	// Clause 11.5.4: a range of one carries no bits at all.
	if span == 1 {
		return lb, nil
	}

	if !d.aligned || span <= RANGE_BITFIELD_MAX {
		width := BitsNonNegativeBinaryInteger(uint64(span - 1))

		return d._ReadOffset(lb, uint8(width))
	}

	if span <= RANGE_TWO_OCTET_MAX {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}

		width := uint8(BITS_PER_BYTE)
		if span > RANGE_ONE_OCTET {
			width = DOUBLE_OCTET_BITS
		}

		return d._ReadOffset(lb, width)
	}

	return d._DecodeIndefinite(lb, uint64(ub-lb))
}

// DecodeNormallySmallNonNegativeWholeNumber reads a number encoded per X.691
// clause 11.6.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeNormallySmallNonNegativeWholeNumber() (uint64, error) {
	bit, err := d.codec.Read(1)
	if err != nil {
		return 0, err
	}

	if bit == 0 {
		return d.codec.Read(NORMALLY_SMALL_BITS)
	}

	value, err := d.DecodeSemiConstrainedWholeNumber(0)

	return uint64(value), err
}

// DecodeSemiConstrainedWholeNumber reads a number encoded per X.691 clause 11.7
// as an offset from lb.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
//   - 2026-09-22 06:43: returns int64 rather than uint64, since the value it
//     reconstructs is lb plus an offset and lb may be negative
func (d *Decoder) DecodeSemiConstrainedWholeNumber(lb int64) (int64, error) {
	raw, _, err := d._ReadOctetAligned()
	if err != nil {
		return 0, err
	}

	return lb + int64(raw), nil
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

	return _SignExtend(raw, width), nil
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

	lower := size._SizeLower()

	value, err := d.DecodeConstrainedWholeNumber(int64(lower), int64(upper))
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
		return 0, false, fmt.Errorf("multiplier %d: %w", multiple, ErrFragmentCount)
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

	lower, hasLower := size.Lower()
	upper, hasUpper := size.Upper()

	switch {
	case hasLower && hasUpper:
		return d.DecodeConstrainedWholeNumber(lower, upper)
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

	value, err := d.DecodeConstrainedWholeNumber(0, upper)
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
		data  = make([]byte, 0, (count+BITS_PER_BYTE-1)/BITS_PER_BYTE)
	)

	if whole > 0 {
		chunk, err := d.codec.ReadBytes(int(whole))
		if err != nil {
			return nil, err
		}

		data = append(data, chunk...)
	}

	if rest == 0 {
		return data, nil
	}

	value, err := d.codec.Read(uint8(rest))
	if err != nil {
		return nil, err
	}

	return append(data, byte(value<<(BITS_PER_BYTE-rest))), nil
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

	return &asn1.BitString{Bytes: data, BitLength: int(fixed)}, nil
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

// DecodeString reads a string whose ASN.1 type is one of X.691 clause 30.5.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation
func (d *Decoder) DecodeString(size *Constraint) (string, error) {
	octets, err := d.DecodeOctetString(size)
	if err != nil {
		return "", err
	}

	return string(octets), nil
}

// DecodeObjectIdentifier reads an OBJECT IDENTIFIER, per X.691 clause 24.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation. EncodeObjectIdentifier had no
//     counterpart, so an OID field decoded as a SEQUENCE OF INTEGER over the
//     same octets and failed on the first component
func (d *Decoder) DecodeObjectIdentifier() (asn1.ObjectIdentifier, error) {
	contents, err := d.DecodeOctetString(Unconstrained())
	if err != nil {
		return nil, err
	}

	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(_DERWrap(asn1.TagOID, contents), &oid); err != nil {
		return nil, fmt.Errorf("object identifier: %w", err)
	}

	return oid, nil
}

// DecodeChoiceId reads the index of a root CHOICE alternative, per X.691
// clauses 23.6 and 23.7.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes the root as a Constraint, and the extension case
//     moved to DecodeChoiceExtensionId
func (d *Decoder) DecodeChoiceId(root *Constraint) (int64, error) {
	lower, _ := root.Lower()
	upper, _ := root.Upper()

	return d.DecodeConstrainedWholeNumber(lower, upper)
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

// DecodeSequence reads a SEQUENCE into the struct target points at, per X.691
// clause 19.
//
// Revisions:
//   - 2026-03-05 18:01: initial creation
func (d *Decoder) DecodeSequence(target any) error {
	rv, err := _Target(target)
	if err != nil {
		return err
	}

	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("sequence is a %s: %w", rv.Kind(), ErrNotStruct)
	}

	meta, err := GetStructMeta(rv.Type())
	if err != nil {
		return err
	}

	return d._DecodeSequence(rv, meta)
}

// DecodeSequenceOf reads a SEQUENCE OF into the slice target points at, per
// X.691 clause 20.
//
// Revisions:
//   - 2026-03-05 18:01: initial creation
func (d *Decoder) DecodeSequenceOf(target any, size *Constraint, elem *Tag) error {
	rv, err := _Target(target)
	if err != nil {
		return err
	}

	if rv.Kind() != reflect.Slice {
		return fmt.Errorf("sequence-of is a %s: %w", rv.Kind(), ErrNotList)
	}

	return d._DecodeSequenceOf(rv, size, elem)
}

// DecodeChoice reads a CHOICE into the struct target points at, per X.691
// clause 23.
//
// Revisions:
//   - 2026-03-05 18:01: initial creation
func (d *Decoder) DecodeChoice(target any) error {
	rv, err := _Target(target)
	if err != nil {
		return err
	}

	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("choice is a %s: %w", rv.Kind(), ErrNotStruct)
	}

	meta, err := GetStructMeta(rv.Type())
	if err != nil {
		return err
	}

	return d._DecodeChoice(rv, meta)
}

// _ReadOffset reads width bits and adds them to lb.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of
//     DecodeConstrainedWholeNumber
func (d *Decoder) _ReadOffset(lb int64, width uint8) (int64, error) {
	value, err := d.codec.Read(width)
	if err != nil {
		return 0, err
	}

	return lb + int64(value), nil
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
		return 0, 0, fmt.Errorf("integer: %w", ErrLengthFragmented)
	}

	if octets == 0 || octets > MAX_VALUE_OCTETS {
		return 0, 0, fmt.Errorf("%d octets: %w", octets, ErrLengthTooLarge)
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
func (d *Decoder) _DecodeIndefinite(lb int64, span uint64) (int64, error) {
	bounds := Constrained(1, int64(OctetsNonNegativeBinaryIntegerLength(span)))

	octets, _, err := d.DecodeLengthDeterminant(bounds)
	if err != nil {
		return 0, err
	}

	if octets == 0 || octets > MAX_VALUE_OCTETS {
		return 0, fmt.Errorf("%d octets: %w", octets, ErrLengthTooLarge)
	}

	if err := d.codec.Advance(); err != nil {
		return 0, err
	}

	return d._ReadOffset(lb, uint8(octets*BITS_PER_BYTE))
}

// _DecodeBitFragments reads a bit string behind a length determinant, following
// the fragments of clause 11.9.3.8.
//
// Revisions:
//   - 2026-02-19 23:40: initial creation as DecodeBitStringFragments
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

		if d.aligned && length > 0 {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}

		chunk, err := d.ReadBits(length)
		if err != nil {
			return nil, err
		}

		data = append(data, chunk...)
		count = count + length

		if !more {
			return &asn1.BitString{Bytes: data, BitLength: int(count)}, nil
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
func (d *Decoder) _DecodeOctetFragments(size *Constraint) ([]byte, error) {
	if err := d._AlignForLength(size); err != nil {
		return nil, err
	}

	var data []byte

	for {
		length, more, err := d.DecodeLengthDeterminant(size)
		if err != nil {
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
			return chunk, nil
		}

		data = append(data, chunk...)

		if !more {
			return data, nil
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

// _Nested returns a Decoder for the same variant, reading an open type's
// contents.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _Nested(data []byte) *Decoder {
	if d.aligned {
		return NewAlignedDecoder(data)
	}

	return NewUnalignedDecoder(data)
}

// _DecodeSequence reads the preamble, root components and extension additions
// of clause 19.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeSequence
func (d *Decoder) _DecodeSequence(rv reflect.Value, meta *StructMeta) error {
	extended := false

	if meta.Extensible {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return err
		}

		extended = outside
	}

	present := make([]bool, len(meta.Optionals))
	for i := range present {
		has, err := d.DecodeBoolean()
		if err != nil {
			return err
		}

		present[i] = has
	}

	if err := d._DecodeRoot(rv, meta, present); err != nil {
		return err
	}

	if !extended {
		return nil
	}

	return d._DecodeExtensions(rv, meta)
}

// _DecodeRoot reads the root components of clause 19.4, giving an absent
// DEFAULT field its default value.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeSequence
func (d *Decoder) _DecodeRoot(rv reflect.Value, meta *StructMeta, present []bool) error {
	var (
		rt     = rv.Type()
		cursor = 0
	)

	for _, idx := range meta.Fields {
		field := rt.Field(idx)

		tag, err := GetFieldTag(field, rt, idx)
		if err != nil {
			return err
		}

		if tag.Optional() {
			has := present[cursor]
			cursor++

			if !has {
				if err := _ApplyAbsent(rv.Field(idx), tag); err != nil {
					return fmt.Errorf("field %q: %w", field.Name, err)
				}

				continue
			}
		}

		if err := d._DecodeField(rv.Field(idx), tag); err != nil {
			return fmt.Errorf("field %q: %w", field.Name, err)
		}
	}

	return nil
}

// _DecodeExtensions reads the extension bitmap of clause 19.7 and the additions
// of clause 19.9, skipping any the struct has no field for.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeSequence
func (d *Decoder) _DecodeExtensions(rv reflect.Value, meta *StructMeta) error {
	count, _, err := d.DecodeNormallySmallLength()
	if err != nil {
		return err
	}

	present := make([]bool, count)
	for i := range present {
		has, err := d.DecodeBoolean()
		if err != nil {
			return err
		}

		present[i] = has
	}

	rt := rv.Type()

	for i, has := range present {
		if !has {
			continue
		}

		inner, err := d.DecodeOctetString(Unconstrained())
		if err != nil {
			return err
		}

		// An addition this version of the type does not know about is read past
		// and dropped, which is what the open type wrapper is for.
		if i >= len(meta.Extensions) {
			continue
		}

		idx := meta.Extensions[i]
		field := rt.Field(idx)

		tag, err := GetFieldTag(field, rt, idx)
		if err != nil {
			return err
		}

		if err := d._Nested(inner)._DecodeField(rv.Field(idx), tag); err != nil {
			return fmt.Errorf("extension %q: %w", field.Name, err)
		}
	}

	return nil
}

// _DecodeSequenceOf reads the extension bit, length and components of clause 20.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeSequenceOf
func (d *Decoder) _DecodeSequenceOf(rv reflect.Value, size *Constraint, elem *Tag) error {
	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return err
		}

		if outside {
			return d._DecodeElements(rv, _Unbounded(), elem)
		}

		size = size._Root()
	}

	// Clause 20.5: a fixed count below 64K needs no length determinant.
	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return d._DecodeElements(rv, size, elem)
	}

	return d._DecodeRange(rv, fixed, elem)
}

// _DecodeElements reads a length determinant and the components it counts,
// following the fragments of clause 11.9.3.8.
//
// Revisions:
//   - 2026-03-05 18:01: initial creation as decodeSequenceOfComponents
func (d *Decoder) _DecodeElements(rv reflect.Value, size *Constraint, elem *Tag) error {
	for {
		length, more, err := d.DecodeLengthDeterminant(size)
		if err != nil {
			return err
		}

		if err := d._DecodeRange(rv, length, elem); err != nil {
			return err
		}

		if !more {
			return nil
		}
	}
}

// _DecodeRange appends count components to a slice.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeRange(rv reflect.Value, count uint64, elem *Tag) error {
	et := rv.Type().Elem()

	for i := range count {
		item := reflect.New(et).Elem()
		if err := d._DecodeField(item, elem); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}

		rv.Set(reflect.Append(rv, item))
	}

	return nil
}

// _DecodeChoice reads the extension bit, index and value of clause 23.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeChoice
func (d *Decoder) _DecodeChoice(rv reflect.Value, meta *StructMeta) error {
	extended := false

	if meta.Extensible {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return err
		}

		extended = outside
	}

	if extended {
		return d._DecodeChoiceExtension(rv, meta)
	}

	root := Constrained(0, int64(len(meta.Fields)-1))

	index, err := d.DecodeChoiceId(root)
	if err != nil {
		return err
	}

	if index < 0 || int(index) >= len(meta.Fields) {
		return fmt.Errorf("root index %d: %w", index, ErrChoiceIndex)
	}

	return d._DecodeAlternative(rv, meta.Fields[int(index)], nil)
}

// _DecodeChoiceExtension reads an extension alternative, per clause 23.8.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of DecodeChoice
func (d *Decoder) _DecodeChoiceExtension(rv reflect.Value, meta *StructMeta) error {
	index, err := d.DecodeChoiceExtensionId()
	if err != nil {
		return err
	}

	inner, err := d.DecodeOctetString(Unconstrained())
	if err != nil {
		return err
	}

	// An alternative this version of the type does not know about is read past
	// and dropped, which is what the open type wrapper is for.
	if index < 0 || int(index) >= len(meta.Extensions) {
		return nil
	}

	return d._DecodeAlternative(rv, meta.Extensions[int(index)], inner)
}

// _DecodeAlternative reads one CHOICE alternative into its field, from the open
// type contents when it is an extension addition and from the stream when it is
// not.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeAlternative(rv reflect.Value, idx int, inner []byte) error {
	var (
		rt    = rv.Type()
		field = rt.Field(idx)
	)

	tag, err := GetFieldTag(field, rt, idx)
	if err != nil {
		return err
	}

	source := d
	if inner != nil {
		source = d._Nested(inner)
	}

	if err := source._DecodeField(rv.Field(idx), tag); err != nil {
		return fmt.Errorf("alternative %q: %w", field.Name, err)
	}

	return nil
}

// _DecodeField reads one struct field or one list element.
//
// Revisions:
//   - 2026-03-05 18:01: initial creation as decodeField
//   - 2026-09-22 06:43: dispatches on the field's reflect.Type rather than on
//     the dynamic type of a boxed copy of it
func (d *Decoder) _DecodeField(v reflect.Value, tag *Tag) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}

		v = v.Elem()
	}

	if tag.open {
		return d._DecodeOpen(v, tag)
	}

	if done, err := d._DecodeWellKnown(v, tag); done {
		return err
	}

	return d._DecodeByKind(v, tag)
}

// _DecodeOpen reads an open type field, per clause 11.2. The concrete value has
// to be in place already, because the wrapper says how long the encoding is and
// nothing about which type it belongs to.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of decodeField
func (d *Decoder) _DecodeOpen(v reflect.Value, tag *Tag) error {
	inner, err := d.DecodeOctetString(Unconstrained())
	if err != nil {
		return err
	}

	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return ErrOpenTypeNil
		}

		concrete := v.Elem()
		if concrete.Kind() == reflect.Pointer && !concrete.IsNil() {
			concrete = concrete.Elem()
		}

		return d._Nested(inner)._DecodeField(concrete, tag._WithoutOpen())
	}

	return d._Nested(inner)._DecodeField(v, tag._WithoutOpen())
}

// _DecodeWellKnown reads a value of one of the standard library types this
// package maps onto an ASN.1 type, and reports whether it did.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of decodeField
func (d *Decoder) _DecodeWellKnown(v reflect.Value, tag *Tag) (bool, error) {
	switch v.Type() {
	case TYPE_BITSTRING:
		value, err := d.DecodeBitString(tag.Constraint())
		if err != nil {
			return true, err
		}

		v.Set(reflect.ValueOf(*value))

		return true, nil
	case TYPE_OID:
		value, err := d.DecodeObjectIdentifier()
		if err != nil {
			return true, err
		}

		v.Set(reflect.ValueOf(value))

		return true, nil
	case TYPE_NULL:
		return true, d.DecodeNull()
	case TYPE_EMPTY:
		return true, d.DecodeNull()
	default:
		return false, nil
	}
}

// _DecodeByKind reads a value according to its Go kind.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of decodeField
func (d *Decoder) _DecodeByKind(v reflect.Value, tag *Tag) error {
	kind := v.Kind()

	switch {
	case kind == reflect.Bool:
		return d._DecodeBool(v)
	case _IsSigned(kind):
		return d._DecodeSigned(v, tag)
	case _IsUnsigned(kind):
		return d._DecodeUnsigned(v, tag)
	case _IsFloat(kind):
		return d._DecodeFloat(v)
	case kind == reflect.String:
		return d._DecodeString(v, tag)
	case kind == reflect.Slice:
		return d._DecodeSlice(v, tag)
	case kind == reflect.Array:
		return d._DecodeArray(v, tag)
	case kind == reflect.Struct:
		return d._DecodeStruct(v)
	default:
		return fmt.Errorf("%s: %w", v.Type(), ErrUnsupportedType)
	}
}

// _DecodeBool reads a BOOLEAN into v.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeBool(v reflect.Value) error {
	value, err := d.DecodeBoolean()
	if err != nil {
		return err
	}

	v.SetBool(value)

	return nil
}

// _DecodeSigned reads an INTEGER into a signed field.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeSigned(v reflect.Value, tag *Tag) error {
	value, err := d.DecodeInteger(tag.Constraint())
	if err != nil {
		return err
	}

	v.SetInt(value)

	return nil
}

// _DecodeUnsigned reads an ENUMERATED or an INTEGER into an unsigned field.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeUnsigned(v reflect.Value, tag *Tag) error {
	if tag.enum == nil {
		value, err := d.DecodeInteger(tag.Constraint())
		if err != nil {
			return err
		}

		v.SetUint(uint64(value))

		return nil
	}

	root := Constrained(0, int64(*tag.enum)-1)
	if tag.ext {
		root = root.Extensible()
	}

	value, err := d.DecodeEnumerated(root)
	if err != nil {
		return err
	}

	v.SetUint(value)

	return nil
}

// _DecodeFloat reads a REAL into v.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeFloat(v reflect.Value) error {
	value, err := d.DecodeReal()
	if err != nil {
		return err
	}

	v.SetFloat(value)

	return nil
}

// _DecodeString reads a restricted character string into v.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeString(v reflect.Value, tag *Tag) error {
	value, err := d.DecodeRestrictedString(tag.kind, tag.Constraint())
	if err != nil {
		return err
	}

	v.SetString(value)

	return nil
}

// _DecodeSlice reads a slice, which is an OCTET STRING when its elements are
// bytes and a SEQUENCE OF otherwise.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeSlice(v reflect.Value, tag *Tag) error {
	if v.Type().Elem().Kind() == reflect.Uint8 {
		value, err := d.DecodeOctetString(tag.Constraint())
		if err != nil {
			return err
		}

		v.SetBytes(value)

		return nil
	}

	return d._DecodeSequenceOf(v, tag.Constraint(), tag.Elem())
}

// _DecodeArray reads an array, whose length its Go type already fixes.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeArray(v reflect.Value, tag *Tag) error {
	elem := tag.Elem()

	for i := range v.Len() {
		if err := d._DecodeField(v.Index(i), elem); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}
	}

	return nil
}

// _DecodeStruct reads a struct, which is a CHOICE when its fields carry choice
// indices and a SEQUENCE otherwise.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeStruct(v reflect.Value) error {
	meta, err := GetStructMeta(v.Type())
	if err != nil {
		return err
	}

	if meta.Choice {
		return d._DecodeChoice(v, meta)
	}

	return d._DecodeSequence(v, meta)
}

// _DERWrap puts a DER tag and length in front of contents octets.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _DERWrap(tag int, contents []byte) []byte {
	if len(contents) <= UNCONSTRAINED_LENGTH_SHORT_MAX {
		return append([]byte{byte(tag), byte(len(contents))}, contents...)
	}

	var (
		width  = OctetsNonNegativeBinaryIntegerLength(uint64(len(contents)))
		header = make([]byte, 0, DER_HEADER_OCTETS+width+len(contents))
	)

	// Appended in place rather than through _Octets, which would allocate the
	// length octets separately only to copy them straight back out.
	header = append(header, byte(tag), byte(LENGTH_MSB_FLAG|width))
	for i := width - 1; i >= 0; i-- {
		header = append(header, byte(len(contents)>>(i*BITS_PER_BYTE)))
	}

	return append(header, contents...)
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

// _Target resolves the pointer a decode writes through.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Target(target any) (reflect.Value, error) {
	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return reflect.Value{}, fmt.Errorf("%T: %w", target, ErrNotPointer)
	}

	return rv.Elem(), nil
}

// _ApplyAbsent gives an absent field its DEFAULT value, per clause 19.5, and
// leaves a plain OPTIONAL field alone.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ApplyAbsent(v reflect.Value, tag *Tag) error {
	if tag.def == nil {
		return nil
	}

	return ApplyDefaultValue(v, *tag.def)
}
