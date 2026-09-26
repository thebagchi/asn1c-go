package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/bits"
	"reflect"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// Sentinel errors reported while encoding.
var (
	ErrValueOutOfRange  = errors.New("value lies outside the type's constraint")
	ErrLengthMismatch   = errors.New("value length differs from the type's fixed size")
	ErrNotStruct        = errors.New("value is not a struct")
	ErrNotList          = errors.New("value is not a slice or an array")
	ErrNilValue         = errors.New("value is nil")
	ErrNoAlternative    = errors.New("choice has no alternative set")
	ErrManyAlternatives = errors.New("choice has more than one alternative set")
	ErrUnsupportedType  = errors.New("type has no PER encoding in this package")
	ErrEnumNoCount      = errors.New("enumerated needs an upper bound for its root")
)

// Encoder writes a PER encoding, in the variant it was created for.
type Encoder struct {
	codec   *bitbuffer.Codec
	aligned bool
}

// NewAlignedEncoder returns an Encoder for the ALIGNED variant, APER.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation as NewEncoder(aligned bool)
//   - 2026-09-22 06:43: split into one constructor per variant, so a call site
//     names the variant instead of passing a bare true or false
func NewAlignedEncoder() *Encoder {
	return &Encoder{
		codec:   bitbuffer.CreateWriter(),
		aligned: true,
	}
}

// NewUnalignedEncoder returns an Encoder for the UNALIGNED variant, UPER.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation as NewEncoder(aligned bool)
//   - 2026-09-22 06:43: split into one constructor per variant
func NewUnalignedEncoder() *Encoder {
	return &Encoder{
		codec:   bitbuffer.CreateWriter(),
		aligned: false,
	}
}

// Bytes returns the encoding written so far, padded to a whole octet.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) Bytes() []byte {
	return e.codec.Bytes()
}

// Aligned reports whether this Encoder writes the ALIGNED variant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) Aligned() bool {
	return e.aligned
}

// EncodeConstrainedWholeNumber encodes n into the field X.691 clause 11.5
// selects from the range, which is ub - lb + 1.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
//   - 2026-09-22 06:43: derives the ALIGNED bit-field width from the range
//     rather than from a table of eight cases, which is the same number the
//     UNALIGNED branch already computed
func (e *Encoder) EncodeConstrainedWholeNumber(lb, ub, n int64) error {
	span := ub - lb + 1

	// Clause 11.5.4: a range of one carries no bits at all.
	if span == 1 {
		return nil
	}

	offset := uint64(n - lb)

	if !e.aligned || span <= RANGE_BITFIELD_MAX {
		width := BitsNonNegativeBinaryInteger(uint64(span - 1))

		return e.codec.Write(uint8(width), offset)
	}

	if span <= RANGE_TWO_OCTET_MAX {
		if err := e.codec.Align(); err != nil {
			return err
		}

		// Clauses 11.5.7.2 and 11.5.7.3: one octet at a range of 256, two up to
		// 64K, whatever the value itself would fit in.
		width := uint8(BITS_PER_BYTE)
		if span > RANGE_ONE_OCTET {
			width = DOUBLE_OCTET_BITS
		}

		return e.codec.Write(width, offset)
	}

	return e._EncodeIndefinite(uint64(ub-lb), offset)
}

// EncodeNormallySmallNonNegativeWholeNumber encodes n per X.691 clause 11.6.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeNormallySmallNonNegativeWholeNumber(n uint64) error {
	if n <= NORMALLY_SMALL_MAX {
		if err := e.codec.Write(1, 0); err != nil {
			return err
		}

		return e.codec.Write(NORMALLY_SMALL_BITS, n)
	}

	if err := e.codec.Write(1, 1); err != nil {
		return err
	}

	return e.EncodeSemiConstrainedWholeNumber(0, int64(n))
}

// EncodeSemiConstrainedWholeNumber encodes n as the offset from lb in the fewest
// octets, behind a length determinant, per X.691 clause 11.7.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeSemiConstrainedWholeNumber(lb, n int64) error {
	offset := uint64(n - lb)

	return e._EncodeOctetAligned(OctetsNonNegativeBinaryIntegerLength(offset), offset)
}

// EncodeUnconstrainedWholeNumber encodes n in two's complement in the fewest
// octets, behind a length determinant, per X.691 clause 11.8.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeUnconstrainedWholeNumber(n int64) error {
	return e._EncodeOctetAligned(OctetsTwosComplementBinaryInteger(n), uint64(n))
}

// EncodeLengthDeterminant encodes the length n, per X.691 clause 11.9, and
// returns how much of n a fragment left for the next determinant.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
//   - 2026-09-22 06:43: takes a Constraint, whose lower bound for a length is
//     zero when the type states none. It required both bounds to be present, so
//     a SIZE(0..10) written without its minimum was encoded as though the length
//     were unconstrained
func (e *Encoder) EncodeLengthDeterminant(n uint64, size *Constraint) (uint64, error) {
	upper, bounded := size._SizeUpper()
	if !bounded || upper >= MAX_CONSTRAINED_LENGTH {
		return e.EncodeUnconstrainedLength(n)
	}

	lower := size._SizeLower()

	return 0, e.EncodeConstrainedWholeNumber(int64(lower), int64(upper), int64(n))
}

// EncodeUnconstrainedLength encodes a length with no upper bound, per X.691
// clauses 11.9.3.6 to 11.9.3.8, and returns what a fragment left over.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeUnconstrainedLength(n uint64) (uint64, error) {
	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return 0, err
		}
	}

	if n <= UNCONSTRAINED_LENGTH_SHORT_MAX {
		return 0, e.codec.Write(BITS_PER_BYTE, n)
	}

	if n < FRAGMENT_SIZE {
		return 0, e.codec.Write(DOUBLE_OCTET_BITS, LENGTH_LONG_FORM_FLAG|n)
	}

	carried := CalculateFragmentSize(n)
	marker := LENGTH_FRAGMENT_FLAG | carried/FRAGMENT_SIZE

	if err := e.codec.Write(BITS_PER_BYTE, marker); err != nil {
		return 0, err
	}

	return n - carried, nil
}

// EncodeNormallySmallLength encodes the length of an extension bitmap, per
// X.691 clause 11.9.3.4.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeNormallySmallLength(n uint64) (uint64, error) {
	if n <= NORMALLY_SMALL_LENGTH_MAX {
		if err := e.codec.Write(1, 0); err != nil {
			return 0, err
		}

		return 0, e.codec.Write(NORMALLY_SMALL_BITS, n-1)
	}

	if err := e.codec.Write(1, 1); err != nil {
		return 0, err
	}

	return e.EncodeUnconstrainedLength(n)
}

// EncodeBoolean encodes a boolean as one bit, per X.691 clause 12.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeBoolean(value bool) error {
	return e.codec.Write(1, _Bit(value))
}

// WriteExtensionBit writes the bit that says whether what follows lies outside
// the extension root, per X.691 clauses 13.1, 14.3, 16.6, 17.3, 19.1, 20.4
// and 23.5.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
func (e *Encoder) WriteExtensionBit(extended bool) error {
	return e.EncodeBoolean(extended)
}

// EncodeInteger encodes an integer under its constraint, per X.691 clause 13.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
//   - 2026-09-22 06:43: rejects a value outside a non-extensible constraint.
//     The offset from the lower bound was written into a field sized for the
//     range and silently truncated there, so 9 in a type constrained to 0..7
//     encoded as 1 and the receiver had no way to know
func (e *Encoder) EncodeInteger(value int64, size *Constraint) error {
	if size.HasExtension() {
		outside := !size._Covers(value)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e.EncodeUnconstrainedWholeNumber(value)
		}

		size = size._Root()
	}

	lower, hasLower := size.Lower()
	upper, hasUpper := size.Upper()

	if (hasLower || hasUpper) && !size._Covers(value) {
		return fmt.Errorf("integer %d: %w", value, ErrValueOutOfRange)
	}

	switch {
	case hasLower && hasUpper:
		return e.EncodeConstrainedWholeNumber(lower, upper, value)
	case hasLower:
		return e.EncodeSemiConstrainedWholeNumber(lower, value)
	default:
		return e.EncodeUnconstrainedWholeNumber(value)
	}
}

// EncodeEnumerated encodes an enumeration index, per X.691 clause 14. root gives
// the indices of the extension root, from zero, and carries the extension marker
// when the type has one.
//
// Revisions:
//   - 2026-01-29 23:50: initial creation
//   - 2026-09-22 06:43: takes the root as a Constraint rather than a count and a
//     flag, and rejects an index outside a root that cannot be extended
func (e *Encoder) EncodeEnumerated(value uint64, root *Constraint) error {
	upper, bounded := root.Upper()
	if !bounded || upper < 0 {
		return ErrEnumNoCount
	}

	count := uint64(upper) + 1

	if root.HasExtension() {
		outside := value >= count
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e.EncodeNormallySmallNonNegativeWholeNumber(value - count)
		}
	}

	if value >= count {
		return fmt.Errorf(
			"enumeration index %d of %d: %w", value, count, ErrValueOutOfRange,
		)
	}

	return e.EncodeConstrainedWholeNumber(0, upper, int64(value))
}

// EncodeReal encodes a real, per X.691 clause 15: the contents octets of X.690
// clause 8.5 behind an unconstrained length determinant.
//
// Revisions:
//   - 2026-02-04 22:23: initial creation
//   - 2026-09-22 06:43: builds the contents with _RealContents, which cannot
//     fail, in place of fifteen unchecked writes into a second bit buffer
func (e *Encoder) EncodeReal(value float64) error {
	return e.EncodeOctetString(_RealContents(value), Unconstrained())
}

// WriteBits writes the leading count bits of data.
//
// Revisions:
//   - 2026-01-31 00:03: initial creation
func (e *Encoder) WriteBits(data []byte, count uint64) error {
	if count == 0 {
		return nil
	}

	if uint64(len(data))*BITS_PER_BYTE < count {
		return fmt.Errorf(
			"%d bits from %d octets: %w", count, len(data), ErrShortBitString,
		)
	}

	whole := count / BITS_PER_BYTE
	if whole > 0 {
		if err := e.codec.WriteBytes(data[:whole]); err != nil {
			return err
		}
	}

	rest := count % BITS_PER_BYTE
	if rest == 0 {
		return nil
	}

	return e.codec.Write(uint8(rest), uint64(data[whole]>>(BITS_PER_BYTE-rest)))
}

// EncodeBitString encodes a bit string under its size constraint, per X.691
// clause 16.
//
// Revisions:
//   - 2026-01-31 00:03: initial creation
//   - 2026-09-22 06:43: checks that the value carries the bits it claims, and
//     that a fixed size gets exactly that many. A BitString whose Bytes were
//     shorter than its BitLength indexed past the slice and panicked, and a
//     fixed-size field wrote the constrained width from whatever followed
func (e *Encoder) EncodeBitString(value *asn1.BitString, size *Constraint) error {
	if value == nil {
		return fmt.Errorf("bit string: %w", ErrNilValue)
	}

	count := uint64(value.BitLength)
	if uint64(len(value.Bytes))*BITS_PER_BYTE < count {
		return fmt.Errorf(
			"%d bits in %d octets: %w",
			count, len(value.Bytes), ErrShortBitString,
		)
	}

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeBitFragments(value.Bytes, count, _Unbounded())
		}

		size = size._Root()
	}

	return e._EncodeBitString(value.Bytes, count, size)
}

// EncodeOctetString encodes an octet string under its size constraint, per X.691
// clause 17.
//
// Revisions:
//   - 2026-01-29 23:50: initial creation
//   - 2026-09-22 06:43: checks a fixed size against the value's own length,
//     which was written without a determinant and so could not be recovered
func (e *Encoder) EncodeOctetString(value []byte, size *Constraint) error {
	count := uint64(len(value))

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeOctetFragments(value, _Unbounded())
		}

		size = size._Root()
	}

	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return e._EncodeOctetFragments(value, size)
	}

	// Clause 17.5: a type fixed at zero octets has no encoding.
	if fixed == 0 {
		return nil
	}

	if count != fixed {
		return fmt.Errorf(
			"octet string of %d in a type fixed at %d: %w",
			count, fixed, ErrLengthMismatch,
		)
	}

	// Clause 17.7 aligns a fixed string above two octets; clause 17.6 leaves a
	// shorter one where it falls.
	if e.aligned && fixed > OCTET_STRING_DIRECT_MAX {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	return e.codec.WriteBytes(value)
}

// EncodeNull encodes a NULL, per X.691 clause 18, which adds nothing.
//
// Revisions:
//   - 2026-01-29 23:50: initial creation
func (e *Encoder) EncodeNull() error {
	return nil
}

// EncodeString encodes a string whose ASN.1 type is one of X.691 clause 30.5,
// such as UTF8String, whose values PER carries as an octet string.
//
// EncodeRestrictedString is what a known-multiplier type needs; this is the
// clause 30.5 half, kept apart because the two pack characters differently.
//
// Revisions:
//   - 2026-02-09 23:42: initial creation
//   - 2026-09-22 06:43: says in its name and its documentation which half of
//     clause 30 it implements, since it was being used for both
func (e *Encoder) EncodeString(value string, size *Constraint) error {
	return e.EncodeOctetString(_StringBytes(value), size)
}

// EncodeObjectIdentifier encodes an OBJECT IDENTIFIER, per X.691 clause 24: the
// contents octets of its BER encoding behind a length determinant.
//
// Revisions:
//   - 2026-02-09 23:42: initial creation
func (e *Encoder) EncodeObjectIdentifier(oid asn1.ObjectIdentifier) error {
	encoded, err := asn1.Marshal(oid)
	if err != nil {
		return fmt.Errorf("object identifier: %w", err)
	}

	contents, err := _DERContents(encoded)
	if err != nil {
		return err
	}

	return e.EncodeOctetString(contents, Unconstrained())
}

// EncodeChoiceId encodes the index of a root CHOICE alternative, per X.691
// clauses 23.6 and 23.7. root gives the indices of the extension root.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes the root as a Constraint, and the extension case
//     moved to EncodeChoiceExtensionId, which is what the flag used to select
func (e *Encoder) EncodeChoiceId(index int64, root *Constraint) error {
	lower, _ := root.Lower()
	upper, _ := root.Upper()

	return e.EncodeConstrainedWholeNumber(lower, upper, index)
}

// EncodeChoiceExtensionId encodes the index of an extension CHOICE alternative,
// per X.691 clause 23.8.
//
// The extension alternatives are numbered from zero again, independently of the
// root, so a caller has to say which list the index belongs to; it cannot be
// worked out from the index itself.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split from EncodeChoiceId
func (e *Encoder) EncodeChoiceExtensionId(index int64) error {
	return e.EncodeNormallySmallNonNegativeWholeNumber(uint64(index))
}

// EncodeSequence encodes a struct as a SEQUENCE, per X.691 clause 19.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
//   - 2026-09-22 06:43: tracks presence in a slice indexed alongside the
//     metadata's optional fields rather than in a map built per call
func (e *Encoder) EncodeSequence(value any) error {
	rv := _Deref(reflect.ValueOf(value))
	if !rv.IsValid() {
		return fmt.Errorf("sequence: %w", ErrNilValue)
	}

	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("sequence is a %s: %w", rv.Kind(), ErrNotStruct)
	}

	meta, err := GetStructMeta(rv.Type())
	if err != nil {
		return err
	}

	return e._EncodeSequence(rv, meta)
}

// EncodeSequenceOf encodes a slice or array as a SEQUENCE OF, per X.691
// clause 20.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
func (e *Encoder) EncodeSequenceOf(value any, size *Constraint, elem *Tag) error {
	rv := _Deref(reflect.ValueOf(value))
	if !rv.IsValid() {
		return fmt.Errorf("sequence-of: %w", ErrNilValue)
	}

	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return fmt.Errorf("sequence-of is a %s: %w", rv.Kind(), ErrNotList)
	}

	return e._EncodeSequenceOf(rv, size, elem)
}

// EncodeChoice encodes a struct as a CHOICE, per X.691 clause 23.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
//   - 2026-09-22 06:43: reports a struct with two alternatives set. The root
//     alternatives were searched first and the extension alternatives only if
//     none was found, so a value carrying one of each encoded the root and
//     dropped the extension without a word
func (e *Encoder) EncodeChoice(value any) error {
	rv := _Deref(reflect.ValueOf(value))
	if !rv.IsValid() {
		return fmt.Errorf("choice: %w", ErrNilValue)
	}

	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("choice is a %s: %w", rv.Kind(), ErrNotStruct)
	}

	meta, err := GetStructMeta(rv.Type())
	if err != nil {
		return err
	}

	return e._EncodeChoice(rv, meta)
}

// _EncodeIndefinite encodes the indefinite length case of X.691 clause 11.5.7.4:
// the value in the fewest octets, behind a length that says how many.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of
//     EncodeConstrainedWholeNumber
func (e *Encoder) _EncodeIndefinite(span, offset uint64) error {
	width := OctetsNonNegativeBinaryIntegerLength(offset)

	// Clause 13.2.6 a): the length is itself constrained, from one octet to as
	// many as the whole range would need.
	bounds := Constrained(1, int64(OctetsNonNegativeBinaryIntegerLength(span)))
	if _, err := e.EncodeLengthDeterminant(uint64(width), bounds); err != nil {
		return err
	}

	if err := e.codec.Align(); err != nil {
		return err
	}

	return e.codec.Write(uint8(width*BITS_PER_BYTE), offset)
}

// _EncodeOctetAligned encodes a value in width octets behind an unconstrained
// length determinant, which is the shape clauses 11.7.4 and 11.8.3 share.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, shared by the semi-constrained and
//     unconstrained whole number encoders
func (e *Encoder) _EncodeOctetAligned(width int, value uint64) error {
	if width == 0 {
		width = 1
	}

	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	if _, err := e.EncodeLengthDeterminant(uint64(width), Unconstrained()); err != nil {
		return err
	}

	return e.codec.Write(uint8(width*BITS_PER_BYTE), value)
}

// _EncodeBitString encodes a bit string whose length lies in the extension root,
// per X.691 clauses 16.8 to 16.11.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeBitString
func (e *Encoder) _EncodeBitString(data []byte, count uint64, size *Constraint) error {
	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return e._EncodeBitFragments(data, count, size)
	}

	// Clause 16.8: a type fixed at zero bits has no encoding.
	if fixed == 0 {
		return nil
	}

	if count != fixed {
		return fmt.Errorf(
			"bit string of %d bits in a type fixed at %d: %w",
			count, fixed, ErrLengthMismatch,
		)
	}

	// Clause 16.10 aligns a fixed string above sixteen bits; clause 16.9 leaves
	// a shorter one where it falls.
	if e.aligned && fixed > BITSTRING_DIRECT_MAX_BITS {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	return e.WriteBits(data, fixed)
}

// _EncodeBitFragments encodes a bit string behind a length determinant,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-01-31 00:03: initial creation as EncodeBitStringFragments
//   - 2026-09-22 06:43: took its alignment decision from the Constraint, which
//     knows that an absent lower bound on a length means zero
func (e *Encoder) _EncodeBitFragments(data []byte, count uint64, size *Constraint) error {
	if err := e._AlignForLength(size); err != nil {
		return err
	}

	offset := uint64(0)

	for {
		pending, err := e.EncodeLengthDeterminant(count-offset, size)
		if err != nil {
			return err
		}

		length := count - offset - pending
		if e.aligned && length > 0 {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}

		if err := e.WriteBits(data[offset/BITS_PER_BYTE:], length); err != nil {
			return err
		}

		offset = offset + length

		if pending != 0 {
			continue
		}

		return e._CloseFragments(count, offset, size)
	}
}

// _EncodeOctetFragments encodes an octet string behind a length determinant,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-01-29 23:50: initial creation as EncodeOctetStringFragments
//   - 2026-09-22 06:43: took its alignment decision from the Constraint
func (e *Encoder) _EncodeOctetFragments(data []byte, size *Constraint) error {
	if err := e._AlignForLength(size); err != nil {
		return err
	}

	var (
		count  = uint64(len(data))
		offset = uint64(0)
	)

	for {
		pending, err := e.EncodeLengthDeterminant(count-offset, size)
		if err != nil {
			return err
		}

		length := count - offset - pending
		if e.aligned && length > 0 {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}

		if err := e.codec.WriteBytes(data[offset : offset+length]); err != nil {
			return err
		}

		offset = offset + length

		if pending != 0 {
			continue
		}

		return e._CloseFragments(count, offset, size)
	}
}

// _AlignForLength aligns before a length determinant that is not a constrained
// whole number, which is the only case clause 11.9.3.5 leaves to the caller;
// EncodeConstrainedWholeNumber aligns for itself, per clause 11.5.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, shared by the three fragmenting
//     encoders, which each carried a copy of it
func (e *Encoder) _AlignForLength(size *Constraint) error {
	if !e.aligned {
		return nil
	}

	if upper, bounded := size._SizeUpper(); bounded && upper < MAX_CONSTRAINED_LENGTH {
		return nil
	}

	return e.codec.Align()
}

// _CloseFragments writes the terminating zero length that clause 11.9.3.8.3
// requires when a fragmented value ended on an exact multiple of 16K.
//
// A length bounded below 64K is written once as a constrained whole number and
// never fragments, however long the value is, so it takes no terminator.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _CloseFragments(count, offset uint64, size *Constraint) error {
	if count < FRAGMENT_SIZE || offset != count {
		return nil
	}

	if upper, bounded := size._SizeUpper(); bounded && upper < MAX_CONSTRAINED_LENGTH {
		return nil
	}

	_, err := e.EncodeLengthDeterminant(0, size)

	return err
}

// _EncodeOpenType writes an inner encoding as an open type field, per X.691
// clause 11.2.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation. The three call sites wrote the inner
//     bytes straight out, so a value whose encoding is empty - a NULL, an
//     integer with one possible value - was carried as a length of zero, where
//     clause 11.1.3 requires the one zero octet an empty complete encoding has
func (e *Encoder) _EncodeOpenType(inner []byte) error {
	if len(inner) == 0 {
		inner = []byte{0}
	}

	return e.EncodeOctetString(inner, Unconstrained())
}

// _Nested returns an Encoder for the same variant, for an inner encoding that
// has to be measured before it is written.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _Nested() *Encoder {
	if e.aligned {
		return NewAlignedEncoder()
	}

	return NewUnalignedEncoder()
}

// _EncodeSequence writes the preamble, the root components and the extension
// additions of clause 19.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeSequence
func (e *Encoder) _EncodeSequence(rv reflect.Value, meta *StructMeta) error {
	present, err := e._EncodePreamble(rv, meta)
	if err != nil {
		return err
	}

	if err := e._EncodeRoot(rv, meta, present); err != nil {
		return err
	}

	return e._EncodeExtensions(rv, meta)
}

// _EncodePreamble writes the extension bit of clause 19.1 and the presence
// bitmap of clause 19.2, and returns what it recorded there.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeSequence
func (e *Encoder) _EncodePreamble(rv reflect.Value, meta *StructMeta) ([]bool, error) {
	if meta.Extensible {
		if err := e.WriteExtensionBit(_HasExtensions(rv, meta)); err != nil {
			return nil, err
		}
	}

	rt := rv.Type()
	present := make([]bool, len(meta.Optionals))

	for i, idx := range meta.Optionals {
		field := rt.Field(idx)

		tag, err := GetFieldTag(field, rt, idx)
		if err != nil {
			return nil, err
		}

		has, err := FieldPresentForEncoding(rv.Field(idx), tag)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", field.Name, err)
		}

		present[i] = has
		if err := e.EncodeBoolean(has); err != nil {
			return nil, err
		}
	}

	return present, nil
}

// _EncodeRoot writes the root components of clause 19.4, skipping those the
// preamble said were absent.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeSequence
func (e *Encoder) _EncodeRoot(rv reflect.Value, meta *StructMeta, present []bool) error {
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
			skip := !present[cursor]
			cursor++

			if skip {
				continue
			}
		}

		if err := e._EncodeField(rv.Field(idx), tag); err != nil {
			return fmt.Errorf("field %q: %w", field.Name, err)
		}
	}

	return nil
}

// _EncodeExtensions writes the extension bitmap of clause 19.7 and the additions
// of clause 19.9, each as an open type field.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeSequence
func (e *Encoder) _EncodeExtensions(rv reflect.Value, meta *StructMeta) error {
	if !meta.Extensible || !_HasExtensions(rv, meta) {
		return nil
	}

	if _, err := e.EncodeNormallySmallLength(uint64(len(meta.Extensions))); err != nil {
		return err
	}

	for _, idx := range meta.Extensions {
		if err := e.EncodeBoolean(FieldPresent(rv.Field(idx))); err != nil {
			return err
		}
	}

	rt := rv.Type()

	for _, idx := range meta.Extensions {
		if !FieldPresent(rv.Field(idx)) {
			continue
		}

		field := rt.Field(idx)

		tag, err := GetFieldTag(field, rt, idx)
		if err != nil {
			return err
		}

		if err := e._EncodeNested(rv.Field(idx), tag); err != nil {
			return fmt.Errorf("extension %q: %w", field.Name, err)
		}
	}

	return nil
}

// _EncodeSequenceOf writes the extension bit, length and components of clause 20.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeSequenceOf
func (e *Encoder) _EncodeSequenceOf(rv reflect.Value, size *Constraint, elem *Tag) error {
	count := uint64(rv.Len())

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeElements(rv, count, _Unbounded(), elem)
		}

		size = size._Root()
	}

	// Clause 20.5: a fixed count below 64K needs no length determinant.
	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return e._EncodeElements(rv, count, size, elem)
	}

	if count != fixed {
		return fmt.Errorf(
			"sequence-of %d in a type fixed at %d: %w",
			count, fixed, ErrLengthMismatch,
		)
	}

	return e._EncodeRange(rv, 0, count, elem)
}

// _EncodeElements writes a length determinant and the components it counts,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation as encodeSequenceOfComponents
func (e *Encoder) _EncodeElements(
	rv reflect.Value,
	count uint64,
	size *Constraint,
	elem *Tag,
) error {
	offset := uint64(0)

	for {
		pending, err := e.EncodeLengthDeterminant(count-offset, size)
		if err != nil {
			return err
		}

		length := count - offset - pending
		if err := e._EncodeRange(rv, offset, length, elem); err != nil {
			return err
		}

		offset = offset + length

		if pending != 0 {
			continue
		}

		return e._CloseFragments(count, offset, size)
	}
}

// _EncodeRange writes length components starting at from.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _EncodeRange(rv reflect.Value, from, length uint64, elem *Tag) error {
	for i := from; i < from+length; i++ {
		if err := e._EncodeField(rv.Index(int(i)), elem); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}
	}

	return nil
}

// _EncodeChoice writes the extension bit, index and value of clause 23.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeChoice
func (e *Encoder) _EncodeChoice(rv reflect.Value, meta *StructMeta) error {
	pos, extended, err := _FindAlternative(rv, meta)
	if err != nil {
		return fmt.Errorf("%v: %w", rv.Type(), err)
	}

	if meta.Extensible {
		if err := e.WriteExtensionBit(extended); err != nil {
			return err
		}
	}

	idx := meta.Fields[pos]
	if extended {
		idx = meta.Extensions[pos]
	}

	var (
		rt    = rv.Type()
		field = rt.Field(idx)
	)

	tag, err := GetFieldTag(field, rt, idx)
	if err != nil {
		return err
	}

	if extended {
		if err := e.EncodeChoiceExtensionId(int64(pos)); err != nil {
			return err
		}

		return e._EncodeNested(rv.Field(idx), tag)
	}

	// Clause 23.4: one root alternative needs no index, which falls out of a
	// range of one carrying no bits.
	root := Constrained(0, int64(len(meta.Fields)-1))
	if err := e.EncodeChoiceId(int64(pos), root); err != nil {
		return err
	}

	return e._EncodeField(rv.Field(idx), tag)
}

// _EncodeNested writes one value as an open type field, per clause 11.2.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, shared by the extension paths of
//     SEQUENCE and CHOICE and by an open type field
func (e *Encoder) _EncodeNested(v reflect.Value, tag *Tag) error {
	inner := e._Nested()
	if err := inner._EncodeField(v, tag); err != nil {
		return err
	}

	return e._EncodeOpenType(inner.Bytes())
}

// _EncodeField writes one struct field or one list element.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation as encodeField
//   - 2026-09-22 06:43: dispatches on the field's reflect.Type rather than on
//     the dynamic type of a boxed copy of it, which allocated for every
//     non-pointer field and panicked for one reached through an unexported one
func (e *Encoder) _EncodeField(v reflect.Value, tag *Tag) error {
	v = _Deref(v)
	if !v.IsValid() || v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		return nil
	}

	if tag.open {
		return e._EncodeNested(v, tag._WithoutOpen())
	}

	if done, err := e._EncodeWellKnown(v, tag); done {
		return err
	}

	return e._EncodeByKind(v, tag)
}

// _EncodeWellKnown writes a value of one of the standard library types this
// package maps onto an ASN.1 type, and reports whether it did.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of encodeField
func (e *Encoder) _EncodeWellKnown(v reflect.Value, tag *Tag) (bool, error) {
	switch v.Type() {
	case TYPE_BITSTRING:
		value := v.Interface().(asn1.BitString)

		return true, e.EncodeBitString(&value, tag.Constraint())
	case TYPE_OID:
		value := v.Interface().(asn1.ObjectIdentifier)

		return true, e.EncodeObjectIdentifier(value)
	case TYPE_NULL:
		return true, e.EncodeNull()
	case TYPE_EMPTY:
		return true, e.EncodeNull()
	default:
		return false, nil
	}
}

// _EncodeByKind writes a value according to its Go kind.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of encodeField
func (e *Encoder) _EncodeByKind(v reflect.Value, tag *Tag) error {
	kind := v.Kind()

	switch {
	case kind == reflect.Bool:
		return e.EncodeBoolean(v.Bool())
	case _IsSigned(kind):
		return e.EncodeInteger(v.Int(), tag.Constraint())
	case _IsUnsigned(kind):
		return e._EncodeUnsigned(v, tag)
	case _IsFloat(kind):
		return e.EncodeReal(v.Float())
	case kind == reflect.String:
		return e.EncodeRestrictedString(v.String(), tag.kind, tag.Constraint())
	case kind == reflect.Slice:
		return e._EncodeSlice(v, tag)
	case kind == reflect.Array:
		return e._EncodeArray(v, tag)
	case kind == reflect.Struct:
		return e._EncodeStruct(v)
	default:
		return fmt.Errorf("%s: %w", v.Type(), ErrUnsupportedType)
	}
}

// _EncodeUnsigned writes an unsigned field, which is an ENUMERATED when the tag
// says how many enumerators its root has and an INTEGER otherwise.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of encodeField
func (e *Encoder) _EncodeUnsigned(v reflect.Value, tag *Tag) error {
	if tag.enum == nil {
		return e.EncodeInteger(int64(v.Uint()), tag.Constraint())
	}

	root := Constrained(0, int64(*tag.enum)-1)
	if tag.ext {
		root = root.Extensible()
	}

	return e.EncodeEnumerated(v.Uint(), root)
}

// _EncodeSlice writes a slice, which is an OCTET STRING when its elements are
// bytes and a SEQUENCE OF otherwise.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of encodeField
func (e *Encoder) _EncodeSlice(v reflect.Value, tag *Tag) error {
	if v.Type().Elem().Kind() == reflect.Uint8 {
		return e.EncodeOctetString(v.Bytes(), tag.Constraint())
	}

	return e._EncodeSequenceOf(v, tag.Constraint(), tag.Elem())
}

// _EncodeArray writes an array, whose length its Go type already fixes.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation. An array was sent through the
//     sequence-of path with the field's own bounds, which wrote a length
//     determinant the decoder never read back, so an array round-tripped to a
//     rotation of itself
func (e *Encoder) _EncodeArray(v reflect.Value, tag *Tag) error {
	return e._EncodeRange(v, 0, uint64(v.Len()), tag.Elem())
}

// _EncodeStruct writes a struct, which is a CHOICE when its fields carry choice
// indices and a SEQUENCE otherwise.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of encodeField
func (e *Encoder) _EncodeStruct(v reflect.Value) error {
	meta, err := GetStructMeta(v.Type())
	if err != nil {
		return err
	}

	if meta.Choice {
		return e._EncodeChoice(v, meta)
	}

	return e._EncodeSequence(v, meta)
}

// BitsNonNegativeBinaryInteger returns the bits a non-negative whole number
// needs, per X.691 clause 11.3. Zero needs one bit, not none.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func BitsNonNegativeBinaryInteger(value uint64) int {
	if value == 0 {
		return 1
	}

	return bits.Len64(value)
}

// OctetsNonNegativeBinaryIntegerLength returns the octets a non-negative whole
// number needs, per X.691 clause 11.3.6.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func OctetsNonNegativeBinaryIntegerLength(value uint64) int {
	return (BitsNonNegativeBinaryInteger(value) + BITS_PER_BYTE - 1) / BITS_PER_BYTE
}

// BitsTwosComplementBinaryInteger returns the bits a whole number needs in two's
// complement, per X.691 clause 11.4.6: the leading nine bits may be neither all
// zero nor all one, which is what the extra sign bit below accounts for.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func BitsTwosComplementBinaryInteger(value int64) int {
	if value == 0 {
		return 1
	}

	if value > 0 {
		return bits.Len64(uint64(value)) + 1
	}

	return bits.Len64(uint64(^value)) + 1
}

// OctetsTwosComplementBinaryInteger returns the octets a whole number needs in
// two's complement, per X.691 clause 11.4.6.
//
// Revisions:
//   - 2026-02-07 01:42: initial creation
func OctetsTwosComplementBinaryInteger(value int64) int {
	return (BitsTwosComplementBinaryInteger(value) + BITS_PER_BYTE - 1) / BITS_PER_BYTE
}

// CalculateFragmentSize returns how much of n a fragment carries, per X.691
// clause 11.9.3.8.1: the largest multiple of 16K, up to four, that n covers.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func CalculateFragmentSize(n uint64) uint64 {
	multiple := n / FRAGMENT_SIZE
	if multiple > FRAGMENT_MULTIPLIER_MAX {
		multiple = FRAGMENT_MULTIPLIER_MAX
	}

	return multiple * FRAGMENT_SIZE
}

// _DERContents strips the tag and length from a DER encoding, leaving the
// contents octets that X.691 clause 24 carries.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeObjectIdentifier
func _DERContents(encoded []byte) ([]byte, error) {
	if len(encoded) < DER_HEADER_OCTETS {
		return nil, fmt.Errorf("der encoding of %d octets: %w", len(encoded), ErrNilValue)
	}

	if encoded[1]&LENGTH_MSB_FLAG == 0 {
		return encoded[DER_HEADER_OCTETS:], nil
	}

	start := DER_HEADER_OCTETS + int(encoded[1]&LENGTH_SIX_BIT_MASK)
	if start > len(encoded) {
		return nil, fmt.Errorf("der length of %d octets: %w", start, ErrNilValue)
	}

	return encoded[start:], nil
}

// _Bit returns the bit X.691 clause 12.1 assigns to a boolean: one for TRUE and
// zero for FALSE.
//
// Go has no branchless conversion from a boolean to a number, so the branch has
// to be somewhere; it is here, in one place, rather than at every caller. The
// parameter is the value being encoded and not a mode, which is why
// .golangci.yml excludes exactly this function from revive's flag-parameter.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeBoolean
func _Bit(datum bool) uint64 {
	if datum {
		return 1
	}

	return 0
}

// _Deref resolves a pointer or interface to the value behind it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Deref(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return v
		}

		v = v.Elem()
	}

	return v
}

// _HasExtensions reports whether any extension addition carries a value, which
// is what the extension bit of clause 19.1 says.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _HasExtensions(rv reflect.Value, meta *StructMeta) bool {
	for _, idx := range meta.Extensions {
		if FieldPresent(rv.Field(idx)) {
			return true
		}
	}

	return false
}

// _FindAlternative returns the position of the one alternative a CHOICE carries,
// and whether it is an extension addition.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeChoice
func _FindAlternative(rv reflect.Value, meta *StructMeta) (int, bool, error) {
	var (
		pos      = 0
		extended = false
		found    = false
	)

	for i, idx := range meta.Fields {
		if !FieldPresent(rv.Field(idx)) {
			continue
		}

		if found {
			return 0, false, ErrManyAlternatives
		}

		pos, extended, found = i, false, true
	}

	for i, idx := range meta.Extensions {
		if !FieldPresent(rv.Field(idx)) {
			continue
		}

		if found {
			return 0, false, ErrManyAlternatives
		}

		pos, extended, found = i, true, true
	}

	if !found {
		return 0, false, ErrNoAlternative
	}

	return pos, extended, nil
}

// _IsSigned reports whether kind is one of Go's signed integer kinds, which
// reflect numbers consecutively.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _IsSigned(kind reflect.Kind) bool {
	return kind >= reflect.Int && kind <= reflect.Int64
}

// _IsUnsigned reports whether kind is one of Go's unsigned integer kinds.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _IsUnsigned(kind reflect.Kind) bool {
	return kind >= reflect.Uint && kind <= reflect.Uint64
}

// _IsFloat reports whether kind is one of Go's floating point kinds.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _IsFloat(kind reflect.Kind) bool {
	return kind == reflect.Float32 || kind == reflect.Float64
}
