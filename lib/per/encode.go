package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/bits"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// Sentinel errors reported while encoding.
var (
	ErrValueOutOfRange = errors.New("value lies outside the type's constraint")
	ErrLengthMismatch  = errors.New("value length differs from the type's fixed size")
	ErrNilValue        = errors.New("value is nil")
	ErrEnumNoCount     = errors.New("enumerated needs an upper bound for its root")
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
// A complete encoding is never empty: X.691 clauses 11.1.3.1 and 11.1.4 make an
// encoding of no bits one octet of zero bits. Clause 11.2 gives the contents of
// an open type the same rule, so an Encoder that holds a nested value follows it
// as well.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
//   - 2026-10-19 11:14: returns one zero octet for an empty encoding (review P3-5)
func (e *Encoder) Bytes() []byte {
	encoded := e.codec.Bytes()
	if len(encoded) == 0 {
		return []byte{0}
	}

	return encoded
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
//   - 2026-10-19 11:14: works on the span ub - lb as a uint64, so INTEGER
//     (-2^63..2^63-1) no longer wraps its range to zero and takes the wrong
//     branch of clause 11.5.7 (review P3-2)
//   - 2026-10-19 11:38: the field selection moved to _EncodeOffset, which EncodeUnsigned
//     shares (review P4)
func (e *Encoder) EncodeConstrainedWholeNumber(
	lb,
	ub,
	n int64,
) error {
	return e._EncodeOffset(
		uint64(ub)-uint64(lb),
		uint64(n)-uint64(lb),
	)
}

// EncodeNormallySmallNonNegativeWholeNumber encodes n per X.691 clause 11.6.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeNormallySmallNonNegativeWholeNumber(n uint64) error {
	if n <= NORMALLY_SMALL_MAX {
		if err := e.codec.Write(
			1,
			0,
		); err != nil {
			return err
		}

		return e.codec.Write(
			NORMALLY_SMALL_BITS,
			n,
		)
	}

	if err := e.codec.Write(
		1,
		1,
	); err != nil {
		return err
	}

	return e.EncodeSemiConstrainedWholeNumber(
		0,
		int64(n),
	)
}

// EncodeSemiConstrainedWholeNumber encodes n as the offset from lb in the fewest
// octets, behind a length determinant, per X.691 clause 11.7.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeSemiConstrainedWholeNumber(
	lb,
	n int64,
) error {
	offset := uint64(n - lb)

	return e._EncodeOctetAligned(
		OctetsNonNegativeBinaryIntegerLength(offset),
		offset,
	)
}

// EncodeUnconstrainedWholeNumber encodes n in two's complement in the fewest
// octets, behind a length determinant, per X.691 clause 11.8.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeUnconstrainedWholeNumber(n int64) error {
	return e._EncodeOctetAligned(
		OctetsTwosComplementBinaryInteger(n),
		uint64(n),
	)
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
//   - 2026-10-19 11:14: refuses a length outside the root of a constraint below 64K. It
//     masked the length to the width of the field (review P3-1)
func (e *Encoder) EncodeLengthDeterminant(
	n uint64,
	size *Constraint,
) (uint64, error) {
	upper, bounded := size._SizeUpper()
	if !bounded || upper >= MAX_CONSTRAINED_LENGTH {
		return e.EncodeUnconstrainedLength(n)
	}

	if err := size._CheckLength(n); err != nil {
		return 0, err
	}

	lower := size._SizeLower()

	return 0, e.EncodeConstrainedWholeNumber(
		int64(lower),
		int64(upper),
		int64(n),
	)
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
		return 0, e.codec.Write(
			BITS_PER_BYTE,
			n,
		)
	}

	if n < FRAGMENT_SIZE {
		return 0, e.codec.Write(
			DOUBLE_OCTET_BITS,
			LENGTH_LONG_FORM_FLAG|n,
		)
	}

	var (
		carried = CalculateFragmentSize(n)
		marker  = LENGTH_FRAGMENT_FLAG | carried/FRAGMENT_SIZE
	)

	if err := e.codec.Write(
		BITS_PER_BYTE,
		marker,
	); err != nil {
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
		if err := e.codec.Write(
			1,
			0,
		); err != nil {
			return 0, err
		}

		return 0, e.codec.Write(
			NORMALLY_SMALL_BITS,
			n-1,
		)
	}

	if err := e.codec.Write(
		1,
		1,
	); err != nil {
		return 0, err
	}

	return e.EncodeUnconstrainedLength(n)
}

// EncodeBoolean encodes a boolean as one bit, per X.691 clause 12.
//
// Revisions:
//   - 2026-01-28 22:17: initial creation
func (e *Encoder) EncodeBoolean(value bool) error {
	return e.codec.Write(
		1,
		_Bit(value),
	)
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
func (e *Encoder) EncodeInteger(
	value int64,
	size *Constraint,
) error {
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

	var (
		lower, hasLower = size.Lower()
		upper, hasUpper = size.Upper()
	)

	if (hasLower || hasUpper) && !size._Covers(value) {
		return fmt.Errorf(
			"integer %d: %w",
			value,
			ErrValueOutOfRange,
		)
	}

	switch {
	case hasLower && hasUpper:
		return e.EncodeConstrainedWholeNumber(
			lower,
			upper,
			value,
		)
	case hasLower:
		return e.EncodeSemiConstrainedWholeNumber(
			lower,
			value,
		)
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
func (e *Encoder) EncodeEnumerated(
	value uint64,
	root *Constraint,
) error {
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
			"enumeration index %d of %d: %w",
			value,
			count,
			ErrValueOutOfRange,
		)
	}

	return e.EncodeConstrainedWholeNumber(
		0,
		upper,
		int64(value),
	)
}

// EncodeReal encodes a real, per X.691 clause 15: the contents octets of X.690
// clause 8.5 behind an unconstrained length determinant.
//
// Revisions:
//   - 2026-02-04 22:23: initial creation
//   - 2026-09-22 06:43: builds the contents with _RealContents, which cannot
//     fail, in place of fifteen unchecked writes into a second bit buffer
func (e *Encoder) EncodeReal(value float64) error {
	return e.EncodeOctetString(
		_RealContents(value),
		Unconstrained(),
	)
}

// WriteBits writes the leading count bits of data.
//
// Revisions:
//   - 2026-01-31 00:03: initial creation
func (e *Encoder) WriteBits(
	data []byte,
	count uint64,
) error {
	if count == 0 {
		return nil
	}

	if uint64(len(data))*BITS_PER_BYTE < count {
		return fmt.Errorf(
			"%d bits from %d octets: %w",
			count,
			len(data),
			ErrShortBitString,
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

	return e.codec.Write(
		uint8(rest),
		uint64(data[whole]>>(BITS_PER_BYTE-rest)),
	)
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
func (e *Encoder) EncodeBitString(
	value *asn1.BitString,
	size *Constraint,
) error {
	if value == nil {
		return fmt.Errorf(
			"bit string: %w",
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

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeBitFragments(
				value.Bytes,
				count,
				_Unbounded(),
			)
		}

		size = size._Root()
	}

	return e._EncodeBitString(
		value.Bytes,
		count,
		size,
	)
}

// EncodeOctetString encodes an octet string under its size constraint, per X.691
// clause 17.
//
// Revisions:
//   - 2026-01-29 23:50: initial creation
//   - 2026-09-22 06:43: checks a fixed size against the value's own length,
//     which was written without a determinant and so could not be recovered
func (e *Encoder) EncodeOctetString(
	value []byte,
	size *Constraint,
) error {
	count := uint64(len(value))

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeOctetFragments(
				value,
				_Unbounded(),
			)
		}

		size = size._Root()
	}

	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return e._EncodeOctetFragments(
			value,
			size,
		)
	}

	// Clause 17.5: a type fixed at zero octets has no encoding.
	if fixed == 0 {
		return nil
	}

	if count != fixed {
		return fmt.Errorf(
			"octet string of %d in a type fixed at %d: %w",
			count,
			fixed,
			ErrLengthMismatch,
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

// EncodeChoiceId encodes the index of a root CHOICE alternative, per X.691
// clauses 23.6 and 23.7. root gives the indices of the extension root.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes the root as a Constraint, and the extension case
//     moved to EncodeChoiceExtensionId, which is what the flag used to select
func (e *Encoder) EncodeChoiceId(
	index int64,
	root *Constraint,
) error {
	var (
		lower, _ = root.Lower()
		upper, _ = root.Upper()
	)

	return e.EncodeConstrainedWholeNumber(
		lower,
		upper,
		index,
	)
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

// _EncodeOffset writes offset into the field X.691 clause 11.5 selects from a
// range of span + 1 values. The range of clause 11.5.3 is not formed, because it
// is 2^64 for the widest type and a uint64 would wrap it.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation, the body of EncodeConstrainedWholeNumber, so that
//     INTEGER above int64 uses the same clause 11.5 logic (review P4)
func (e *Encoder) _EncodeOffset(
	span,
	offset uint64,
) error {
	// Clause 11.5.4: a range of one carries no bits at all.
	if span == 0 {
		return nil
	}

	if !e.aligned || span < RANGE_BITFIELD_MAX {
		width := BitsNonNegativeBinaryInteger(span)

		return e.codec.Write(
			uint8(width),
			offset,
		)
	}

	if span < RANGE_TWO_OCTET_MAX {
		if err := e.codec.Align(); err != nil {
			return err
		}

		// Clauses 11.5.7.2 and 11.5.7.3: one octet at a range of 256, two up to
		// 64K, whatever the value itself would fit in.
		width := uint8(BITS_PER_BYTE)
		if span >= RANGE_ONE_OCTET {
			width = DOUBLE_OCTET_BITS
		}

		return e.codec.Write(
			width,
			offset,
		)
	}

	return e._EncodeIndefinite(
		span,
		offset,
	)
}

// _EncodeIndefinite encodes the indefinite length case of X.691 clause 11.5.7.4:
// the value in the fewest octets, behind a length that says how many.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of
//     EncodeConstrainedWholeNumber
func (e *Encoder) _EncodeIndefinite(
	span,
	offset uint64,
) error {
	var (
		width = OctetsNonNegativeBinaryIntegerLength(offset)

		// Clause 13.2.6 a): the length is itself constrained, from one octet to as
		// many as the whole range would need.
		bounds = Constrained(
			1,
			int64(OctetsNonNegativeBinaryIntegerLength(span)),
		)
	)
	if _, err := e.EncodeLengthDeterminant(
		uint64(width),
		bounds,
	); err != nil {
		return err
	}

	if err := e.codec.Align(); err != nil {
		return err
	}

	return e.codec.Write(
		uint8(width*BITS_PER_BYTE),
		offset,
	)
}

// _EncodeOctetAligned encodes a value in width octets behind an unconstrained
// length determinant, which is the shape clauses 11.7.4 and 11.8.3 share.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, shared by the semi-constrained and
//     unconstrained whole number encoders
func (e *Encoder) _EncodeOctetAligned(
	width int,
	value uint64,
) error {
	if width == 0 {
		width = 1
	}

	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	if _, err := e.EncodeLengthDeterminant(
		uint64(width),
		Unconstrained(),
	); err != nil {
		return err
	}

	return e.codec.Write(
		uint8(width*BITS_PER_BYTE),
		value,
	)
}

// _EncodeBitString encodes a bit string whose length lies in the extension root,
// per X.691 clauses 16.8 to 16.11.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeBitString
func (e *Encoder) _EncodeBitString(
	data []byte,
	count uint64,
	size *Constraint,
) error {
	fixed, isFixed := size.Fixed()
	if !isFixed || fixed >= MAX_CONSTRAINED_LENGTH {
		return e._EncodeBitFragments(
			data,
			count,
			size,
		)
	}

	// Clause 16.8: a type fixed at zero bits has no encoding.
	if fixed == 0 {
		return nil
	}

	if count != fixed {
		return fmt.Errorf(
			"bit string of %d bits in a type fixed at %d: %w",
			count,
			fixed,
			ErrLengthMismatch,
		)
	}

	// Clause 16.10 aligns a fixed string above sixteen bits; clause 16.9 leaves
	// a shorter one where it falls.
	if e.aligned && fixed > BITSTRING_DIRECT_MAX_BITS {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	return e.WriteBits(
		data,
		fixed,
	)
}

// _EncodeBitFragments encodes a bit string behind a length determinant,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-01-31 00:03: initial creation as EncodeBitStringFragments
//   - 2026-09-22 06:43: took its alignment decision from the Constraint, which
//     knows that an absent lower bound on a length means zero
//   - 2026-10-19 11:14: refuses a length outside the size constraint (review P3-1)
func (e *Encoder) _EncodeBitFragments(
	data []byte,
	count uint64,
	size *Constraint,
) error {
	if err := size._CheckLength(count); err != nil {
		return err
	}

	if err := e._AlignForLength(size); err != nil {
		return err
	}

	offset := uint64(0)

	for {
		pending, err := e.EncodeLengthDeterminant(
			count-offset,
			size,
		)
		if err != nil {
			return err
		}

		length := count - offset - pending
		if e.aligned && length > 0 {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}

		if err := e.WriteBits(
			data[offset/BITS_PER_BYTE:],
			length,
		); err != nil {
			return err
		}

		offset = offset + length

		if pending != 0 {
			continue
		}

		return e._CloseFragments(
			count,
			offset,
			size,
		)
	}
}

// _EncodeOctetFragments encodes an octet string behind a length determinant,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-01-29 23:50: initial creation as EncodeOctetStringFragments
//   - 2026-09-22 06:43: took its alignment decision from the Constraint
//   - 2026-10-19 11:14: refuses a length outside the size constraint (review P3-1)
func (e *Encoder) _EncodeOctetFragments(
	data []byte,
	size *Constraint,
) error {
	count := uint64(len(data))
	if err := size._CheckLength(count); err != nil {
		return err
	}

	if err := e._AlignForLength(size); err != nil {
		return err
	}

	offset := uint64(0)

	for {
		pending, err := e.EncodeLengthDeterminant(
			count-offset,
			size,
		)
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

		return e._CloseFragments(
			count,
			offset,
			size,
		)
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
// requires when a fragmented value ended on an exact multiple of 16K. A value
// that ends in a remainder has already written that remainder as its last
// length, and takes no terminator.
//
// A length bounded below 64K is written once as a constrained whole number and
// never fragments, however long the value is, so it takes no terminator.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 11:40: writes the terminator only when the count is a multiple of 16K. It
//     wrote one after every value above 16K, so 16385 octets ended in a spurious
//     zero octet (found by the IRI vectors, review P4)
func (e *Encoder) _CloseFragments(
	count,
	offset uint64,
	size *Constraint,
) error {
	if count < FRAGMENT_SIZE || offset != count || count%FRAGMENT_SIZE != 0 {
		return nil
	}

	if upper, bounded := size._SizeUpper(); bounded && upper < MAX_CONSTRAINED_LENGTH {
		return nil
	}

	_, err := e.EncodeLengthDeterminant(
		0,
		size,
	)

	return err
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
