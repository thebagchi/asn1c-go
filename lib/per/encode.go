package per

import (
	"encoding/asn1"
	"math"
	"math/bits"
	"unsafe"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// Encoder represents a PER encoder for bit-level encoding
type Encoder struct {
	codec   *bitbuffer.Codec
	aligned bool
}

// NewEncoder creates a new PER encoder
// aligned: true for APER (Aligned PER), false for UPER (Unaligned PER)
func NewEncoder(aligned bool) *Encoder {
	return &Encoder{
		codec:   bitbuffer.CreateWriter(),
		aligned: aligned,
	}
}

// Bytes returns the encoded bytes, correctly trimmed to the exact bit length
func (e *Encoder) Bytes() []byte {
	return e.codec.Bytes()
}

// 11.3 Encoding as a non-negative-binary-integer
// |- NOTE - (Tutorial) This subclause gives precision to the term
// |  |  "non-negative-binary-integer encoding", putting the integer into a field which is a
// |  |  fixed number of bits, a field which is a fixed number of octets, or a field that is
// |  |  the minimum number of octets needed to hold it.
// |- 11.3.1 Subsequent subclauses refer to the generation of a non-negative-binary-integer
// |  |  encoding of a non-negative whole number into a field which is either a bit-field of
// |  |  specified length, a single octet, a double octet, or the minimum number of octets
// |  |  for the value.
// |  |  This subclause (11.3) specifies the precise encoding to be applied when such
// |  |  references are made.
// |- 11.3.2 The leading bit of the field is defined as the leading bit of the bit-field, or
// |  |  as the most significant bit of the first octet in the field, and the trailing bit of
// |  |  the field is defined as the trailing bit of the bit-field or as the least significant
// |  |  bit of the last octet in the field.
// |- 11.3.3 For the following definition only, the bits shall be numbered zero for the
// |  |  trailing bit of the field, one for the next bit, and so on up to the leading bit of
// |  |  the field.
// |- 11.3.4 In a non-negative-binary-integer encoding, the value of the whole number
// |  |  represented by the encoding shall be the sum of the values specified by each bit.
// |  |  A bit which is set to "0" has zero value.
// |  |  A bit with number "n" which is set to "1" has the value 2^n.
// |- 11.3.5 The encoding which sums (as defined above) to the value being encoded is an
// |  |  encoding of that value.
// |  |- NOTE - Where the size of the encoded field is fixed (a bit-field of specified
// |  |  |  length, a single octet, or a double octet), then there is a unique encoding which
// |  |  |  sums to the value being encoded.
// |- 11.3.6 A minimum octet non-negative-binary-integer encoding of the whole number (which
// |  |  does not predetermine the number of octets to be used for the encoding) has a field
// |  |  which is a multiple of eight bits and also satisfies the condition that the leading
// |  |  eight bits of the field shall not all be zero unless the field is precisely eight
// |  |  bits long.
// |  |- NOTE - This is a necessary and sufficient condition to produce a unique encoding.

func BitsNonNegativeBinaryInteger(value uint64) int {
	if value == 0 {
		return 1
	}
	return bits.Len64(value)
}

func OctetsNonNegativeBinaryIntegerLength(value uint64) int {
	bits := BitsNonNegativeBinaryInteger(value)
	return (bits + 7) >> 3
}

// 11.4 Encoding as a 2's-complement-binary-integer
// |- NOTE - (Tutorial) This subclause gives precision to the term
// |  |  "2's-complement-binary-integer encoding", putting a signed integer into a field
// |  |  that is the minimum number of octets needed to hold it.
// |  |  These procedures are referenced in later encoding specifications.
// |- 11.4.1 Subsequent subclauses refer to the generation of a 2's-complement-binary-integer
// |  |  encoding of a whole number (which may be negative, zero, or positive) into the minimum
// |  |  number of octets for the value.
// |  |  This subclause (11.4) specifies the precise encoding to be applied when such
// |  |  references are made.
// |- 11.4.2 The leading bit of the field is defined as the most significant bit of the first
// |  |  octet, and the trailing bit of the field is defined as the least significant bit of
// |  |  the last octet.
// |- 11.4.3 For the following definition only, the bits shall be numbered zero for the
// |  |  trailing bit of the field, one for the next bit, and so on up to the leading bit of
// |  |  the field.
// |- 11.4.4 In a 2's-complement-binary-integer encoding, the value of the whole number
// |  |  represented by the encoding shall be the sum of the values specified by each bit.
// |  |  A bit which is set to "0" has zero value.
// |  |  A bit with number "n" which is set to "1" has the value 2^n unless it is the leading
// |  |  bit, in which case it has the (negative) value -2^n.
// |- 11.4.5 Any encoding which sums (as defined above) to the value being encoded is an
// |  |  encoding of that value.
// |- 11.4.6 A minimum octet 2's-complement-binary-integer encoding of the whole number has a
// |  |  field-width that is a multiple of eight bits and also satisfies the condition that the
// |  |  leading nine bits of the field shall not all be zero and shall not all be ones.
// |  |- NOTE - This is a necessary and sufficient condition to produce a unique encoding.

func BitsTwosComplementBinaryInteger(value int64) int {
	if value == 0 {
		return 1
	}
	if value > 0 {
		return bits.Len64(uint64(value)) + 1
	}
	// For negative values, ensure "leading nine bits shall not all be ones" per spec 11.4.6
	// Use bitwise NOT to find minimum bits, then +1 for proper sign extension
	return bits.Len64(uint64(^value)) + 1
}

func OctetsTwosComplementBinaryInteger(value int64) int {
	bits := BitsTwosComplementBinaryInteger(value)
	return (bits + 7) >> 3
}

// 11.5 Encoding of a constrained whole number
// |- NOTE - (Tutorial) This subclause is referenced by other clauses, and itself references
// |  |  earlier clauses for the production of a non-negative-binary-integer or a
// |  |  2's-complement-binary-integer encoding.
// |  |  For the UNALIGNED variant the value is always encoded in the minimum number of bits
// |  |  necessary to represent the range (defined in 11.5.3).
// |  |  The rest of this Note addresses the ALIGNED variant.
// |  |  Where the range is less than or equal to 255, the value encodes into a bit-field of
// |  |  the minimum size for the range.
// |  |  Where the range is exactly 256, the value encodes into a single octet octet-aligned
// |  |  bit-field.
// |  |  Where the range is 257 to 64K, the value encodes into a two octet octet-aligned
// |  |  bit-field.
// |  |  Where the range is greater than 64K, the range is ignored and the value encodes into
// |  |  an octet-aligned bit-field which is the minimum number of octets for the value.
// |  |  In this latter case, later procedures (see 11.9) also encode a length field (usually a
// |  |  single octet) to indicate the length of the encoding.
// |  |  For the other cases, the length of the encoding is independent of the value being
// |  |  encoded, and is not explicitly encoded.
// |- 11.5.1 This subclause (11.5) specifies a mapping from a constrained whole number into
// |  |  either a bit-field (unaligned) or a bit-field (octet-aligned in the ALIGNED variant),
// |  |  and is invoked by later clauses in this Recommendation | International Standard.
// |- 11.5.2 The procedures of this subclause are invoked only if a constrained whole number to
// |  |  be encoded is available, and the values of the lower bound, "lb", and the upper bound,
// |  |  "ub", have been determined from the type notation (after the application of PER-visible
// |  |  constraints).
// |  |- NOTE - A lower bound cannot be determined if MIN evaluates to an infinite number, nor
// |  |  |  can an upper bound be determined if MAX evaluates to an infinite number.
// |  |  |  For example, no upper or lower bound can be determined for INTEGER(MIN..MAX).
// |- 11.5.3 Let "range" be defined as the integer value ("ub" - "lb" + 1), and let the value
// |  |  to be encoded be "n".
// |- 11.5.4 If "range" has the value 1, then the result of the encoding shall be an empty
// |  |  bit-field (no bits).
// |- 11.5.5 There are five other cases (leading to different encodings) to consider, where one
// |  |  applies to the UNALIGNED variant and four to the ALIGNED variant.
// |- 11.5.6 In the case of the UNALIGNED variant the value ("n" - "lb") shall be encoded as a
// |  |  non-negative-binary-integer in a bit-field as specified in 11.3 with the minimum
// |  |  number of bits necessary to represent the range.
// |  |- NOTE - If "range" satisfies the inequality 2m < "range" <= 2m + 1, then the number of
// |  |  |  bits = m + 1.
// |- 11.5.7 In the case of the ALIGNED variant the encoding depends on whether:
// |  |  a) "range" is less than or equal to 255 (the bit-field case);
// |  |  b) "range" is exactly 256 (the one-octet case);
// |  |  c) "range" is greater than 256 and less than or equal to 64K (the two-octet case);
// |  |  d) "range" is greater than 64K (the indefinite length case).
// |  |- 11.5.7.1 (The bit-field case.) If "range" is less than or equal to 255, then invocation
// |  |  |  of this subclause requires the generation of a bit-field with a number of bits as
// |  |  |  specified in the table below, and containing the value ("n" - "lb") as a
// |  |  |  non-negative-binary-integer encoding in a bit-field as specified in 11.3.
// |  |  |
// |  |  |  +-------------+--------------------------+
// |  |  |  | "range"     | Bit-field size (in bits) |
// |  |  |  |-------------|--------------------------|
// |  |  |  | 2           | 1                        |
// |  |  |  | 3, 4        | 2                        |
// |  |  |  | 5, 6, 7, 8  | 3                        |
// |  |  |  | 9 to 16     | 4                        |
// |  |  |  | 17 to 32    | 5                        |
// |  |  |  | 33 to 64    | 6                        |
// |  |  |  | 65 to 128   | 7                        |
// |  |  |  | 129 to 255  | 8                        |
// |  |  |  +-------------+--------------------------+
// |  |- 11.5.7.2 (The one-octet case.) If the range has a value of 256, then the value ("n" -
// |  |  |  "lb") shall be encoded in a one-octet bit-field (octet-aligned in the ALIGNED
// |  |  |  variant) as a non-negative-binary-integer as specified in 11.3.
// |  |- 11.5.7.3 (The two-octet case.) If the "range" has a value greater than or equal to 257
// |  |  |  and less than or equal to 64K, then the value ("n" - "lb") shall be encoded in a
// |  |  |  two-octet bit-field (octet-aligned in the ALIGNED variant) as a
// |  |  |  non-negative-binary-integer encoding as specified in 11.3.
// |  |- 11.5.7.4 (The indefinite length case.) Otherwise, the value ("n" - "lb") shall be
// |  |  |  encoded as a non-negative-binary-integer in a bit-field (octet-aligned in the
// |  |  |  ALIGNED variant) with the minimum number of octets as specified in 11.3, and the
// |  |  |  number of octets "len" used in the encoding is used by other clauses that reference
// |  |  |  this subclause to specify an encoding of the length.

func (e *Encoder) EncodeConstrainedWholeNumber(lb, ub, n int64) error {
	vr := ub - lb + 1
	if vr == 1 {
		return nil
	}

	if !e.aligned {
		bits := BitsNonNegativeBinaryInteger(uint64(vr - 1))
		value := uint64(n - lb)
		return e.codec.Write(uint8(bits), value)
	}

	value := uint64(n - lb)
	// 11.5.7.1: Bit-field case (range <= 255) - NO alignment, just encode in minimum bits
	if vr <= 0xFF {
		var bits int
		switch {
		case vr == 0x02:
			bits = 1
		case vr >= 0x03 && vr <= 0x04:
			bits = 2
		case vr >= 0x05 && vr <= 0x08:
			bits = 3
		case vr >= 0x09 && vr <= 0x10:
			bits = 4
		case vr >= 0x11 && vr <= 0x20:
			bits = 5
		case vr >= 0x21 && vr <= 0x40:
			bits = 6
		case vr >= 0x41 && vr <= 0x80:
			bits = 7
		case vr >= 0x81 && vr <= 0xFF:
			bits = 8
		}
		return e.codec.Write(uint8(bits), value)
	}
	// 11.5.7.2: One-octet case (range = 256) - octet-aligned
	if vr == 0x100 {
		if err := e.codec.Align(); nil != err {
			return err
		}
		return e.codec.Write(8, value)
	}
	// 11.5.7.3: Two-octet case (range 257-64K) - octet-aligned
	if vr >= 0x101 && vr <= 0x10000 {
		if err := e.codec.Align(); nil != err {
			return err
		}
		return e.codec.Write(16, value)
	}
	// 11.5.7.4: Indefinite length case (range > 64K)
	// For ranges > 0x10000, use constrained encoding with length determinant
	// Per ITU-T X.691 section 13.2.6(a): use constrained length determinant
	// where lb=1 and ub=octets needed to hold the range
	octets := OctetsNonNegativeBinaryIntegerLength(value)
	if octets == 0 {
		octets = 1
	}
	// Calculate constrained length bounds per spec 13.2.6(a)
	var (
		octetsRange = OctetsNonNegativeBinaryIntegerLength(uint64(ub - lb))
		lbRange     = uint64(1)
		ubRange     = uint64(octetsRange)
	)
	// Encode length determinant (constrained whole number, handles its own alignment per 11.5)
	_, err := e.EncodeLengthDeterminant(uint64(octets), &lbRange, &ubRange)
	if err != nil {
		return err
	}
	// 11.5.7.4: Value is octet-aligned
	if err := e.codec.Align(); nil != err {
		return err
	}
	return e.codec.Write(uint8(octets*8), value)
}

// 11.6 Encoding of a normally small non-negative whole number
// |- NOTE - (Tutorial) This procedure is used when encoding a non-negative whole number that is
// |  |  expected to be small, but whose size is potentially unlimited due to the presence of an
// |  |  extension marker.
// |  |  An example is a choice index.
// |- 11.6.1 If the non-negative whole number, "n", is less than or equal to 63, then a
// |  |  single-bit bit-field shall be appended to the field-list with the bit set to 0, and
// |  |  "n" shall be encoded as a non-negative-binary-integer into a 6-bit bit-field.
// |- 11.6.2 If "n" is greater than or equal to 64, a single-bit bit-field with the bit set to 1
// |  |  shall be appended to the field-list.
// |  |  The value "n" shall then be encoded as a semi-constrained whole number with "lb" equal to
// |  |  0 and the procedures of 11.9 shall be invoked to add it to the field-list preceded by a
// |  |  length determinant.

func (e *Encoder) EncodeNormallySmallNonNegativeWholeNumber(n uint64) error {
	if n <= 63 {
		// 11.6.1: bit set to 0, followed by 6-bit encoding of n
		if err := e.codec.Write(1, 0); err != nil {
			return err
		}
		return e.codec.Write(6, n)
	} else {
		if err := e.codec.Write(1, 1); err != nil {
			return err
		}
		return e.EncodeSemiConstrainedWholeNumber(0, int64(n))
	}
}

// 11.7 Encoding of a semi-constrained whole number
// |- NOTE - (Tutorial) This procedure is used when a lower bound can be identified but not an
// |  |  upper bound.
// |  |  The encoding procedure places the offset from the lower bound into the minimum number of
// |  |  octets as a non-negative-binary-integer, and requires an explicit length encoding
// |  |  (typically a single octet) as specified in later procedures.
// |- 11.7.1 This subclause specifies a mapping from a semi-constrained whole number into a
// |  |  bit-field (octet-aligned in the ALIGNED variant), and is invoked by later clauses in this
// |  |  Recommendation | International Standard.
// |- 11.7.2 The procedures of this subclause (11.7) are invoked only if a semi-constrained whole
// |  |  number ("n" say) to be encoded is available, and the value of "lb" has been determined
// |  |  from the type notation (after the application of PER-visible constraints).
// |  |- NOTE - A lower bound cannot be determined if MIN evaluates to an infinite number.
// |  |  |  For example, no lower bound can be determined for INTEGER(MIN..MAX).
// |- 11.7.3 The procedures of this subclause always produce the indefinite length case.
// |- 11.7.4 (The indefinite length case.) The value ("n" - "lb") shall be encoded as a
// |  |  non-negative-binary-integer in a bit-field (octet-aligned in the ALIGNED variant) with
// |  |  the minimum number of octets as specified in 11.3, and the number of octets "len" used
// |  |  in the encoding is used by other clauses that reference this subclause to specify an
// |  |  encoding of the length.

func (e *Encoder) EncodeSemiConstrainedWholeNumber(lb, n int64) error {
	octets := OctetsNonNegativeBinaryIntegerLength(uint64(n - lb))
	if octets == 0 {
		octets = 1
	}
	// 11.7.4: octet-aligned in the ALIGNED variant only
	if e.aligned {
		if err := e.codec.Align(); nil != err {
			return err
		}
	}
	_, err := e.EncodeLengthDeterminant(uint64(octets), nil, nil)
	if err != nil {
		return err
	}
	return e.codec.Write(uint8(octets*8), uint64(n-lb))
}

// 11.8 Encoding of an unconstrained whole number
// |- NOTE - (Tutorial) This case only arises in the encoding of the value of an integer type
// |  |  with no lower bound.
// |  |  The procedure encodes the value as a 2's-complement-binary-integer into the minimum
// |  |  number of octets required to accommodate the encoding, and requires an explicit length
// |  |  encoding (typically a single octet) as specified in later procedures.
// |- 11.8.1 This subclause (11.8) specifies a mapping from an unconstrained whole number
// |  |  ("n" say) into a bit-field (octet-aligned in the ALIGNED variant), and is invoked by
// |  |  later clauses in this Recommendation | International Standard.
// |- 11.8.2 The procedures of this subclause always produce the indefinite length case.
// |- 11.8.3 (The indefinite length case.) The value "n" shall be encoded as a
// |  |  2's-complement-binary-integer in a bit-field (octet-aligned in the ALIGNED variant)
// |  |  with the minimum number of octets as specified in 11.4, and the number of octets "len"
// |  |  used in the encoding is used by other clauses that reference this subclause to specify
// |  |  an encoding of the length.

func (e *Encoder) EncodeUnconstrainedWholeNumber(n int64) error {
	octets := OctetsTwosComplementBinaryInteger(n)
	if octets == 0 {
		octets = 1
	}
	// 11.8.3: octet-aligned in the ALIGNED variant only
	if e.aligned {
		if err := e.codec.Align(); nil != err {
			return err
		}
	}
	_, err := e.EncodeLengthDeterminant(uint64(octets), nil, nil)
	if err != nil {
		return err
	}
	return e.codec.Write(uint8(octets*8), uint64(n))
}

// 11.9 General rules for encoding a length determinant
// |- NOTE 1 - (Tutorial) The procedures of this subclause are invoked when an explicit length
// |  |  field is needed for some part of the encoding regardless of whether the length count is
// |  |  bounded above (by PER-visible constraints) or not.
// |  |  The part of the encoding to which the length applies may be a bit string (with the length
// |  |  count in bits), an octet string (with the length count in octets), a known-multiplier
// |  |  character string (with the length count in characters), or a list of fields (with the
// |  |  length count in components of a sequence-of or set-of).
// |- NOTE 2 - (Tutorial) In the case of the ALIGNED variant if the length count is bounded above
// |  |  by an upper bound that is less than 64K, then the constrained whole number encoding is
// |  |  used for the length.
// |  |  For sufficiently small ranges the result is a bit-field, otherwise the unconstrained
// |  |  length ("n" say) is encoded into an octet-aligned bit-field in one of three ways (in
// |  |  order of increasing size):
// |  |  a) ("n" less than 128) a single octet containing "n" with bit 8 set to zero;
// |  |  b) ("n" less than 16K) two octets containing "n" with bit 8 of the first octet set to 1
// |  |     and bit 7 set to zero;
// |  |  c) (large "n") a single octet containing a count "m" with bit 8 set to 1 and bit 7 set
// |  |     to 1.
// |  |     The count "m" is one to four, and the length indicates that a fragment of the
// |  |     material follows (a multiple "m" of 16K items).
// |  |     For all values of "m", the fragment is then followed by another length encoding for
// |  |     the remainder of the material.
// |- NOTE 3 - (Tutorial) In the UNALIGNED variant, if the length count is bounded above by an
// |  |  upper bound that is less than 64K, then the constrained whole number encoding is used
// |  |  to encode the length in the minimum number of bits necessary to represent the range.
// |  |  Otherwise, the unconstrained length ("n" say) is encoded into a bit-field in the
// |  |  manner described above in Note 2.
// |- 11.9.1 This subclause is not invoked if, in accordance with the specification of later
// |  |  clauses, the value of the length determinant, "n", is fixed by the type definition
// |  |  (constrained by PER-visible constraints) to a value less than 64K.
// |- 11.9.2 This subclause is invoked for addition to the field-list of a field, or list of
// |  |  fields, preceded by a length determinant "n" which determines either:
// |  |  a) the length in octets of an associated field (units are octets); or
// |  |  b) the length in bits of an associated field (units are bits); or
// |  |  c) the number of component encodings in an associated list of fields (units are
// |  |     components of a set-of or sequence-of); or
// |  |  d) the number of characters in the value of an associated known-multiplier character
// |  |     string type (units are characters).
// |- 11.9.3 (ALIGNED variant) The procedures for the ALIGNED variant are specified in
// |  |  11.9.3.1 to 11.9.3.8.4.
// |  |  (The procedures for the UNALIGNED variant are specified in 11.9.4.)
// |  |- 11.9.3.1 As a result of the analysis of the type definition (specified in later
// |  |  |  clauses) the length determinant (a whole number "n") will have been determined to be
// |  |  |  either:
// |  |  |  a) a normally small length with a lower bound "lb" equal to one; or
// |  |  |  b) a constrained whole number with a lower bound "lb" (greater than or equal to
// |  |  |     zero), and an upper bound "ub" less than 64K; or
// |  |  |  c) a semi-constrained whole number with a lower bound "lb" (greater than or equal
// |  |  |     to zero), or a constrained whole number with a lower bound "lb" (greater than or
// |  |  |     equal to zero) and an upper bound "ub" greater than or equal to 64K.
// |  |- 11.9.3.2 The subclauses invoking the procedures of this subclause will have determined
// |  |  |  a value for "lb", the lower bound of the length (this is zero if the length is
// |  |  |  unconstrained), and for "ub", the upper bound of the length.
// |  |  |  "ub" is unset if there is no upper bound determinable from PER-visible constraints.
// |  |- 11.9.3.3 Where the length determinant is a constrained whole number with "ub" less
// |  |  |  than 64K, then the field-list shall have appended to it the encoding of the
// |  |  |  constrained whole number for the length determinant as specified in 11.5.
// |  |  |  If "n" is non-zero, this shall be followed by the associated field or list of
// |  |  |  fields, completing these procedures.
// |  |  |  If "n" is zero there shall be no further addition to the field-list, completing
// |  |  |  these procedures.
// |  |- 11.9.3.4 Where the length determinant is a normally small length and "n" is less
// |  |  |  than or equal to 64, a single-bit bit-field shall be appended to the field-list
// |  |  |  with the bit set to 0, and the value "n-1" shall be encoded as a
// |  |  |  non-negative-binary-integer into a 6-bit bit-field.
// |  |  |  This shall be followed by the associated field, completing these procedures.
// |  |  |  If "n" is greater than 64, a single-bit bit-field shall be appended to the
// |  |  |  field-list with the bit set to 1, followed by the encoding of "n" as an
// |  |  |  unconstrained length determinant followed by the associated field, according to the
// |  |  |  procedures of 11.9.3.5 to 11.9.3.8.4.
// |  |  |- NOTE - Normally small lengths are only used to indicate the length of the bitmap
// |  |  |  |  that prefixes the extension addition values of a set or sequence type.
// |  |- 11.9.3.5 Otherwise (unconstrained length, or large "ub"), "n" is encoded and
// |  |  |  appended to the field-list followed by the associated fields as specified below.
// |  |  |- NOTE - The lower bound, "lb", does not affect the length encodings specified in
// |  |  |  |  11.9.3.6 to 11.9.3.8.4.
// |  |- 11.9.3.6 If "n" is less than or equal to 127, then "n" shall be encoded as a
// |  |  |  non-negative-binary-integer (using the procedures of 11.3) into bits 7 (most
// |  |  |  significant) to 1 (least significant) of a single octet and bit 8 shall be set to
// |  |  |  zero.
// |  |  |  This shall be appended to the field-list as a bit-field (octet-aligned in the
// |  |  |  ALIGNED variant) followed by the associated field or list of fields, completing
// |  |  |  these procedures.
// |  |  |- NOTE - For example, if in the following a value of A is 4 characters long, and
// |  |  |  |  that of B is 4 items long:
// |  |  |  |  A ::= IA5String
// |  |  |  |  B ::= SEQUENCE (SIZE (4..123456)) OF INTEGER
// |  |  |  |  both values are encoded with the length octet occupying one octet, and with
// |  |  |  |  the most significant set to 0 to indicate that the length is less than or equal
// |  |  |  |  to 127:
// |  |  |  |
// |  |  |  |  +--------------------+--------------------+
// |  |  |  |  | 0 ...  0000100     | 4 characters/items |
// |  |  |  |  +--------------------+--------------------+
// |  |  |  |  | Length             | Value              |
// |  |  |  |  +--------------------+--------------------+
// |  |- 11.9.3.7 If "n" is greater than 127 and less than 16K, then "n" shall be encoded
// |  |  |  as a non-negative-binary-integer (using the procedures of 11.3) into bit 6 of
// |  |  |  octet one (most significant) to bit 1 of octet two (least significant) of a
// |  |  |  two-octet bit-field (octet-aligned in the ALIGNED variant) with bit 8 of the
// |  |  |  first octet set to 1 and bit 7 of the first octet set to zero.
// |  |  |  This shall be appended to the field-list followed by the associated field or list
// |  |  |  of fields, completing these procedures.
// |  |  |- NOTE - If in the example of 11.9.3.6 a value of A is 130 characters long, and a
// |  |  |  |  value of B is 130 items long, both values are encoded with the length
// |  |  |  |  component occupying 2 octets, and with the two most significant bits (bits 8
// |  |  |  |  and 7) of the octet set to 10 to indicate that the length is greater than 127
// |  |  |  |  but less than 16K.
// |  |  |  |
// |  |  |  |  +-------------------------+---------------------+
// |  |  |  |  | 10 ... 000000 10000010  | 130 characters/items|
// |  |  |  |  +-------------------------+---------------------+
// |  |  |  |  | Length                  | Value               |
// |  |  |  |  +-------------------------+---------------------+
// |  |- 11.9.3.8 If "n" is greater than or equal to 16K, then there shall be appended to
// |  |  |  the field-list a single octet in a bit-field (octet-aligned in the ALIGNED
// |  |  |  variant) with bit 8 set to 1 and bit 7 set to 1, and bits 6 to 1 encoding the
// |  |  |  value 1, 2, 3 or 4 as a non-negative-binary-integer (using the procedures of
// |  |  |  11.8).
// |  |  |  This single octet shall be followed by part of the associated field or list of
// |  |  |  fields, as specified below.
// |  |  |- NOTE - The value of bits 6 to 1 is restricted to 1-4 (instead of the theoretical
// |  |  |  |  limits of 0-63) so as to limit the number of items that an implementation has
// |  |  |  |  to have knowledge of to a more manageable number (64K instead of 1024K).
// |  |  |- 11.9.3.8.1 The value of bits 6 to 1 (1 to 4) shall be multiplied by 16K giving
// |  |  |  |  a count ("m" say).
// |  |  |  |  The choice of the integer in bits 6 to 1 shall be the maximum allowed value
// |  |  |  |  such that the associated field or list of fields contains more than or exactly
// |  |  |  |  "m" octets, bits, components or characters, as appropriate.
// |  |  |  |- NOTE 1 - The unfragmented form handles lengths up to 16K.
// |  |  |  |  |  The fragmentation therefore provides for lengths up to 64K with a
// |  |  |  |  |  granularity of 16K.
// |  |  |  |- NOTE 2 - If in the example of 11.9.3.6 a value of "B" is 144K + 1 (i.e., 64K
// |  |  |  |  |  + 64K + 16K + 1) items long, the value is fragmented, with the two most
// |  |  |  |  |  significant bits (bits 8 and 7) of the first three fragments set to 11 to
// |  |  |  |  |  indicate that one to four blocks each of 16K items follow, and that another
// |  |  |  |  |  length component will follow the last block of each fragment:
// |  |  |  |  |
// |  |  |  |  |  +-----+--------+------------------------------+
// |  |  |  |  |  | 11  | 000100 | 64K items                    |
// |  |  |  |  |  +-----+--------+------------------------------+
// |  |  |  |  |  | 11  | 000100 | 64K items                    |
// |  |  |  |  |  +-----+--------+------------------------------+
// |  |  |  |  |  | 11  | 000001 | 16K items                    |
// |  |  |  |  |  +-----+--------+------------------------------+
// |  |  |  |  |  | 0   | 000001 | 1 item                       |
// |  |  |  |  |  +--------------+------------------------------+
// |  |  |  |  |  | Length       | Value                        |
// |  |  |  |  |  +--------------+------------------------------+
// |  |  |- 11.9.3.8.2 That part of the contents specified by "m" shall then be appended to
// |  |  |  |  the field-list as either:
// |  |  |  |  a) a single bit-field (octet-aligned in the ALIGNED variant) of "m" octets
// |  |  |  |     containing the first "m" octets of the associated field, for units which
// |  |  |  |     are octets; or
// |  |  |  |  b) a single bit-field (octet-aligned in the ALIGNED variant) of "m" bits
// |  |  |  |     containing the first "m" bits of the associated field, for units which are
// |  |  |  |     bits; or
// |  |  |  |  c) the list of fields encoding the first "m" components in the associated
// |  |  |  |     list of fields, for units which are components of a set-of or sequence-of
// |  |  |  |     types; or
// |  |  |  |  d) a single bit-field (octet-aligned in the ALIGNED variant) of "m"
// |  |  |  |     characters containing the first "m" characters of the associated field, for
// |  |  |  |     units which are characters.
// |  |  |- 11.9.3.8.3 The procedures of 11.9 shall then be reapplied to add the remaining
// |  |  |  |  part of the associated field or list of fields to the field-list with a length
// |  |  |  |  which is a semi-constrained whole number equal to ("n" - "m") with a lower
// |  |  |  |  bound of zero.
// |  |  |  |- NOTE - If the last fragment that contains part of the encoded value has a
// |  |  |  |  |  length that is an exact multiple of 16K, it is followed by a final fragment
// |  |  |  |  |  that consists only of a single octet length component set to 0.
// |  |  |- 11.9.3.8.4 The addition of only a part of the associated field(s) to the field-list
// |  |  |  |  with reapplication of these procedures is called the fragmentation procedure.
// |- 11.9.4 (UNALIGNED variant) The procedures for the UNALIGNED variant are specified in
// |  |  11.9.4.1 to 11.9.4.2.
// |  |  (The procedures for the ALIGNED variant are specified in 11.9.3.)
// |  |- 11.9.4.1 If the length determinant "n" to be encoded is a constrained whole number
// |  |  |  with "ub" less than 64K, then ("n"-"lb") shall be encoded as a
// |  |  |  non-negative-binary-integer (as specified in 11.3) using the minimum number of bits
// |  |  |  necessary to encode the "range" ("ub" - "lb" + 1), unless "range" is 1, in which
// |  |  |  case there shall be no length encoding.
// |  |  |  If "n" is non-zero this shall be followed by an associated field or list of
// |  |  |  fields, completing these procedures.
// |  |  |  If "n" is zero there shall be no further addition to the field-list, completing
// |  |  |  these procedures.
// |  |  |- NOTE - If "range" satisfies the inequality 2m < "range" <= 2m + 1, then the
// |  |  |  |  number of bits in the length determinant is m + 1.
// |  |- 11.9.4.2 If the length determinant "n" to be encoded is a normally small length,
// |  |  |  or a constrained whole number with "ub" greater than or equal to 64K, or is a
// |  |  |  semi-constrained whole number, then "n" shall be encoded as specified in
// |  |  |  11.9.3.4 to 11.9.3.8.4.
// |  |  |- NOTE - Thus, if "ub" is greater than or equal to 64K, the encoding of the length
// |  |  |  |  determinant is the same as it would be if the length were unconstrained.

func (e *Encoder) EncodeLengthDeterminant(n uint64, lb *uint64, ub *uint64) (uint64, error) {
	// 11.9.3.3 / 11.9.4.1: constrained when "ub" is less than MAX_CONSTRAINED_LENGTH
	if ub != nil && lb != nil && *ub < MAX_CONSTRAINED_LENGTH {
		err := e.EncodeConstrainedWholeNumber(int64(*lb), int64(*ub), int64(n))
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	return e.EncodeUnconstrainedLength(n)
}

func (e *Encoder) EncodeUnconstrainedLength(n uint64) (uint64, error) {
	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return 0, err
		}
	}

	if n <= 127 {
		if err := e.codec.Write(8, n); err != nil {
			return 0, err
		}
		return 0, nil
	}

	if n < FRAGMENT_SIZE {
		value := (1 << 15) | n
		if err := e.codec.Write(16, value); err != nil {
			return 0, err
		}
		return 0, nil
	}

	m := CalculateFragmentSize(n)
	k := m / FRAGMENT_SIZE

	value := (3 << 6) | k
	if err := e.codec.Write(8, value); err != nil {
		return 0, err
	}
	return n - m, nil
}

func (e *Encoder) EncodeNormallySmallLength(n uint64) (uint64, error) {
	if n <= 64 {
		if err := e.codec.Write(1, 0); err != nil {
			return 0, err
		}
		if err := e.codec.Write(6, n-1); err != nil {
			return 0, err
		}
		return 0, nil
	}

	if err := e.codec.Write(1, 1); err != nil {
		return 0, err
	}
	return e.EncodeUnconstrainedLength(n)
}

func CalculateFragmentSize(n uint64) uint64 {
	if n >= 4*FRAGMENT_SIZE {
		return 4 * FRAGMENT_SIZE // 64K
	} else if n >= 3*FRAGMENT_SIZE {
		return 3 * FRAGMENT_SIZE // 48K
	} else if n >= 2*FRAGMENT_SIZE {
		return 2 * FRAGMENT_SIZE // 32K
	} else {
		return FRAGMENT_SIZE // 16K
	}
}

// 12 Encoding the boolean type
// |- NOTE - A value of the boolean type shall be encoded as a bit-field consisting of a single
// |  |  bit.
// |- 12.1 The bit shall be set to 1 for TRUE and 0 for FALSE.
// |- 12.2 The bit-field shall be appended to the field-list with no length determinant.

func (e *Encoder) EncodeBoolean(value bool) error {
	if value {
		return e.codec.Write(1, 1)
	} else {
		return e.codec.Write(1, 0)
	}
}

// 13 Encoding the integer type
// |- NOTE 1 - (Tutorial ALIGNED variant) Ranges which allow the encoding of all values into one
// |  |  octet or less go into a minimum-sized bit-field with no length count.
// |  |  Ranges which allow encoding of all values into two octets go into two octets in an
// |  |  octet-aligned bit-field with no length count.
// |  |  Otherwise, the value is encoded into the minimum number of octets (using
// |  |  non-negative-binary-integer or 2's-complement-binary-integer encoding as appropriate) and
// |  |  a length determinant is added.
// |  |  In this case, if the integer value can be encoded in less than 127 octets (as an offset
// |  |  from any lower bound that might be determined), and there is no finite upper and lower
// |  |  bound, there is a one-octet length determinant, else the length is encoded in the fewest
// |  |  number of bits needed.
// |  |  Other cases are not of any practical interest, but are specified for completeness.
// |- NOTE 2 - (Tutorial UNALIGNED variant) Constrained integers are encoded in the fewest number
// |  |  of bits necessary to represent the range regardless of its size.
// |  |  Unconstrained integers are encoded as in Note 1.
// |- 13.1 If an extension marker is present in the constraint specification of the integer type,
// |  |  then a single bit shall be added to the field-list in a bit-field of length one.
// |  |  The bit shall be set to 1 if the value to be encoded is not within the range of the
// |  |  extension root, and zero otherwise.
// |  |  In the former case, the value shall be added to the field-list as an unconstrained
// |  |  integer value, as specified in 13.2.4 to 13.2.6, completing this procedure.
// |  |  In the latter case, the value shall be encoded as if the extension marker is not present.
// |- 13.2 If an extension marker is not present in the constraint specification of the integer
// |  |  type, then the following applies.
// |  |- 13.2.1 If PER-visible constraints restrict the integer value to a single value, then
// |  |  |  there shall be no addition to the field-list, completing these procedures.
// |  |- 13.2.2 If PER-visible constraints restrict the integer value to be a constrained whole
// |  |  |  number, then it shall be converted to a field according to the procedures of 11.5
// |  |  |  (encoding of a constrained whole number), and the procedures of 13.2.5 to 13.2.6
// |  |  |  shall then be applied.
// |  |- 13.2.3 If PER-visible constraints restrict the integer value to be a semi-constrained
// |  |  |  whole number, then it shall be converted to a field according to the procedures of
// |  |  |  11.7 (encoding of a semi-constrained whole number), and the procedures of 13.2.6
// |  |  |  shall then be applied.
// |  |- 13.2.4 If PER-visible constraints do not restrict the integer to be either a constrained
// |  |  |  or a semi-constrained whole number, then it shall be converted to a field according
// |  |  |  to the procedures of 11.8 (encoding of an unconstrained whole number), and the
// |  |  |  procedures of 13.2.6 shall then be applied.
// |  |- 13.2.5 If the procedures invoked to encode the integer value into a field did not produce
// |  |  |  the indefinite length case (see 11.5.7.4 and 11.8.2), then that field shall be appended
// |  |  |  to the field-list completing these procedures.
// |  |- 13.2.6 Otherwise, (the indefinite length case) the procedures of 11.9 shall be invoked
// |  |  |  to append the field to the field-list preceded by one of the following:
// |  |  |- a) A constrained length determinant "len" (as determined by 11.5.7.4) if PER-visible
// |  |  |  |  constraints restrict the type with finite upper and lower bounds and, if the type
// |  |  |  |  is extensible, the value lies within the range of the extension root.
// |  |  |  |  The lower bound "lb" used in the length determinant shall be 1, and the upper
// |  |  |  |  bound "ub" shall be the count of the number of octets required to hold the range
// |  |  |  |  of the integer value.
// |  |  |  |- NOTE - The encoding of the value "foo INTEGER (256..1234567) ::= 256" would thus
// |  |  |  |  |  be encoded in the ALIGNED variant as 00xxxxxx00000000, where each 'x' represents
// |  |  |  |  |  a zero pad bit that may or may not be present depending on where within the
// |  |  |  |  |  octet the length occurs (e.g., the encoding is 00 xxxxxx 00000000 if the length
// |  |  |  |  |  starts on an octet boundary, and 00 00000000 if it starts with the two least
// |  |  |  |  |  significant bits (bits 2 and 1) of an octet).
// |  |  |- b) An unconstrained length determinant equal to "len" (as determined by 11.7 and
// |  |  |  |  11.8) if PER-visible constraints do not restrict the type with finite upper and
// |  |  |  |  lower bounds, or if the type is extensible and the value does not lie within the
// |  |  |  |  range of the extension root.

func (e *Encoder) EncodeInteger(value int64, lb *int64, ub *int64, extensible bool) error {
	if extensible {
		extended := false
		if lb != nil && value < *lb {
			extended = true
		}
		if ub != nil && value > *ub {
			extended = true
		}

		switch extended {
		case true:
			if err := e.codec.Write(1, 1); err != nil {
				return err
			}
		case false:
			if err := e.codec.Write(1, 0); err != nil {
				return err
			}
		}

		if extended {
			return e.EncodeUnconstrainedWholeNumber(value)
		}
	}

	if lb != nil && ub != nil && *lb == *ub {
		return nil
	}

	if lb != nil && ub != nil {
		return e.EncodeConstrainedWholeNumber(*lb, *ub, value)
	} else if lb != nil && ub == nil {
		return e.EncodeSemiConstrainedWholeNumber(*lb, value)
	} else {
		return e.EncodeUnconstrainedWholeNumber(value)
	}
}

// 14 Encoding the enumerated type
// |- NOTE - (Tutorial) An enumerated type without an extension marker is encoded as if it
// |  |  were a constrained integer whose subtype constraint does not contain an extension
// |  |  marker.
// |  |  This means that an enumerated type will almost always in practice be encoded as a
// |  |  bit-field in the smallest number of bits needed to express every enumeration.
// |  |  In the presence of an extension marker, it is encoded as a normally small
// |  |  non-negative whole number if the value is not in the extension root.
// |- 14.1 The enumerations in the enumeration root shall be sorted into ascending order by
// |  |  their enumeration value, and shall then be assigned an enumeration index starting
// |  |  with zero for the first enumeration, one for the second, and so on up to the last
// |  |  enumeration in the sorted list.
// |  |  The extension additions (which are always defined in ascending order) shall be
// |  |  assigned an enumeration index starting with zero for the first enumeration, one for
// |  |  the second, and so on up to the last enumeration in the extension additions.
// |  |- NOTE - Rec. ITU-T X.680 | ISO/IEC 8824-1 requires that each successive extension
// |  |  |  addition shall have a greater enumeration value than the last.
// |- 14.2 If the extension marker is absent in the definition of the enumerated type, then
// |  |  the enumeration index shall be encoded.
// |  |  Its encoding shall be as though it were a value of a constrained integer type for
// |  |  which there is no extension marker present, where the lower bound is 0 and the
// |  |  upper bound is the largest enumeration index associated with the type, completing
// |  |  this procedure.
// |- 14.3 If the extension marker is present, then a single bit shall be added to the
// |  |  field-list in a bit-field of length one.
// |  |  The bit shall be set to 1 if the value to be encoded is not within the extension
// |  |  root, and zero otherwise.
// |  |  In the former case, the enumeration additions shall be sorted according to 14.1
// |  |  and the value shall be added to the field-list as a normally small non-negative
// |  |  whole number whose value is the enumeration index of the additional enumeration and
// |  |  with "lb" set to 0, completing this procedure.
// |  |  In the latter case, the value shall be encoded as if the extension marker is not
// |  |  present, as specified in 14.2.
// |  |- NOTE - There are no PER-visible constraints that can be applied to an enumerated
// |  |  |  type that are visible to these encoding rules.

func (e *Encoder) EncodeEnumerated(value uint64, count uint64, extensible bool) error {
	if extensible {
		if value >= count {
			if err := e.codec.Write(1, 1); err != nil {
				return err
			}
			return e.EncodeNormallySmallNonNegativeWholeNumber(value - count)
		}
		if err := e.codec.Write(1, 0); err != nil {
			return err
		}
	}

	lb := int64(0)
	ub := int64(count - 1)
	return e.EncodeConstrainedWholeNumber(lb, ub, int64(value))
}

// 15 Encoding the real type
// |- NOTE - (Tutorial) A real uses the contents octets of CER/DER preceded by a length
// |  |  determinant that will in practice be a single octet.
// |- 15.1 If the base of the abstract value is 10, then the base of the encoded value shall
// |  |  be 10, and if the base of the abstract value is 2 the base of the encoded value
// |  |  shall be 2.
// |- 15.2 The encoding of REAL specified for CER and DER in Rec. ITU-T X.690 |
// |  |  ISO/IEC 8825-1, 11.3 shall be applied to give a bit-field (octet-aligned in the
// |  |  ALIGNED variant) which is the contents octets of the CER/DER encoding.
// |  |  The contents octets of this encoding consists of "n" (say) octets and is placed in
// |  |  a bit-field (octet-aligned in the ALIGNED variant) of "n" octets.
// |  |  The procedures of 11.9 shall be invoked to append this bit-field (octet-aligned in
// |  |  the ALIGNED variant) of "n" octets to the field-list, preceded by an unconstrained
// |  |  length determinant equal to "n".

// 11.3 Real values
// |- 11.3.1 If the encoding represents a real value whose base B is 2, then binary encoding
// |  |  employing base 2 shall be used.
// |  |  Before encoding, the mantissa M and exponent E are chosen so that M is either 0 or is odd.
// |  |  NOTE – This is necessary because the same real value can be regarded as both {M, 2, E}
// |  |  and {M', 2, E'} with M ≠ M' if, for some non-zero integer n:
// |  |  M' = M  2–n
// |  |  E' = E + n
// |  |  In encoding the value, the binary scaling factor F shall be zero, and M and E shall
// |  |  each be represented in the fewest octets necessary.
// |- 11.3.2 If the encoding represents a real value whose base B is 10, then decimal encoding
// |  |  shall be used. In forming the encoding, the following applies:
// |  |- 11.3.2.1 The ISO 6093 NR3 form shall be used (see 8.5.8).
// |  |- 11.3.2.2 SPACE shall not be used within the encoding.
// |  |- 11.3.2.3 If the real value is negative, then it shall begin with a MINUS SIGN (–),
// |  |  |  otherwise, it shall begin with a digit.
// |  |- 11.3.2.4 Neither the first nor the last digit of the mantissa may be a 0.
// |  |- 11.3.2.5 The last digit in the mantissa shall be immediately followed by FULL STOP (.),
// |  |  |  followed by the exponent-mark "E".
// |  |- 11.3.2.6 If the exponent has the value 0, it shall be written "+0", otherwise the
// |  |  |  exponent's first digit shall not be zero, and PLUS SIGN shall not be used.

// 8.5 Encoding of a real value
// |- 8.5.1 The encoding of a real value shall be primitive.
// |- 8.5.2 If the real value is the value plus zero, there shall be no contents octets in the encoding.
// |- 8.5.3 If the real value is the value minus zero, then it shall be encoded as specified in 8.5.9.
// |- 8.5.4 For a non-zero real value, if the base of the abstract value is 10, then the base of the
// |  |  encoded value shall be 10, and if the base of the abstract value is 2 the base of the
// |  |  encoded value shall be 2, 8 or 16 as a sender's option.
// |- 8.5.5 If the real value is non-zero, then the base used for the encoding shall be B' as specified
// |  |  in 8.5.4. If B' is 2, 8 or 16, a binary encoding, specified in 8.5.7, shall be used. If B' is
// |  |  10, a character encoding, specified in 8.5.8, shall be used.
// |- 8.5.6
// |- Bit 8 of the first contents octet shall be set as follows:
// |  |- a) if bit 8 = 1, then the binary encoding specified in 8.5.7 applies;
// |  |- b) if bit 8 = 0 and bit 7 = 0, then the decimal encoding specified in 8.5.8 applies;
// |  |- c) if bit 8 = 0 and bit 7 = 1, then either a "SpecialRealValue" (see Rec. ITU-T X.680 |
// |  |  |  ISO/IEC 8824-1) or the value minus zero is encoded as specified in 8.5.9.
// 8.5.7
// |- When binary encoding is used (bit 8 = 1), then if the mantissa M is non-zero, it shall be
// |  |  represented by a sign S, a positive integer value N and a binary scaling factor F, such that:
// |  |  M = S × N × 2^F
// |  |  0 ≤ F < 4
// |  |  S = +1 or –1
// |- NOTE – The binary scaling factor F is required under certain circumstances in order to align
// |  |  the implied point of the mantissa to the position required by the encoding rules of this
// |  |  subclause. This alignment cannot always be achieved by modification of the exponent E. If
// |  |  the base B' used for encoding is 8 or 16, the implied point can only be moved in steps of
// |  |  3 or 4 bits, respectively, by changing the component E. Therefore, values of the binary
// |  |  scaling factor F other than zero may be required in order to move the implied point to the
// |  |  required position.
// 8.5.7.1
// |- Bit 7 of the first contents octets shall be 1 if S is –1 and 0 otherwise.
// 8.5.7.2
// |- Bits 6 to 5 of the first contents octets shall encode the value of the base B' as follows:
// |  |  Bits 6 to 5 | Base
// |  |  00          | base 2
// |  |  01          | base 8
// |  |  10          | base 16
// |  |  11          | Reserved for further editions of this Recommendation | International Standard.
// 8.5.7.3
// |- Bits 4 to 3 of the first contents octet shall encode the value of the binary scaling
// |  |  factor F as an unsigned binary integer.
// 8.5.7.4
// |- (Encoding of the mantissa and exponent is specified in 8.5.7.5)
// 8.5.7.5
// |- Bits 2 to 1 of the first contents octet shall encode the format of the exponent as follows:
// |  |- a) if bits 2 to 1 are 00, then the second contents octet encodes the value of the exponent
// |  |  |  as a two's complement binary number;
// |  |- b) if bits 2 to 1 are 01, then the second and third contents octets encode the value of
// |  |  |  the exponent as a two's complement binary number;
// |  |- c) if bits 2 to 1 are 10, then the second, third and fourth contents octets encode the
// |  |  |  value of the exponent as a two's complement binary number;
// |  |- d) if bits 2 to 1 are 11, then the second contents octet encodes the number of octets, X
// |  |  |  say, (as an unsigned binary number) used to encode the value of the exponent, and the
// |  |  |  third up to the (X plus 3)th (inclusive) contents octets encode the value of the
// |  |  |  exponent as a two's complement binary number; the value of X shall be at least one; the
// |  |  |  first nine bits of the transmitted exponent shall not be all zeros or all ones.
// |- The remaining contents octets encode the value of the integer N (see 8.5.7) as an unsigned
// |  |  binary number.
// |- NOTE 1 – For non-canonical BER there is no requirement for floating point normalization of
// |  |  the mantissa. This allows an implementer to transmit octets containing the mantissa without
// |  |  performing shift functions on the mantissa in memory. In the Canonical Encoding Rules and
// |  |  the Distinguished Encoding Rules normalization is specified and the mantissa (unless it is
// |  |  0) needs to be repeatedly shifted until the least significant bit is a 1.
// |- NOTE 2 – This representation of real numbers is very different from the formats normally
// |  |  used in floating point hardware, but has been designed to be easily converted to and from
// |  |  such formats (see Annex C).
// |- 8.5.8 Decimal encoding of real values
// |  |- When decimal encoding is used (bits 8 to 7 = 00), all the contents octets following the
// |  |  |  first contents octet form a field, as the term is used in ISO 6093, of a length chosen
// |  |  |  by the sender, and encoded according to ISO 6093. The choice of ISO 6093 number
// |  |  |  representation is specified by bits 6 to 1 of the first contents octet as follows:
// |  |  |  Bits 6 to 1: Number representation
// |  |  |  00 0001: ISO 6093 NR1 form
// |  |  |  00 0010: ISO 6093 NR2 form
// |  |  |  00 0011: ISO 6093 NR3 form
// |  |  |  The remaining values of bits 6 to 1 are reserved for further editions of this
// |  |  |  Recommendation | International Standard.
// |  |- There shall be no use of scaling factors specified in accompanying documentation
// |  |  |  (see ISO 6093).
// |  |- NOTE 1 – The recommendations in ISO 6093 concerning the use of at least one digit to the
// |  |  |  left of the decimal mark are also recommended in this Recommendation | International
// |  |  |  Standard, but are not mandatory.
// |  |- NOTE 2 – Use of the normalized form (see ISO 6093) is a sender's option, and has no
// |  |  |  significance.
// |- 8.5.9 Special Real Values and minus zero encoding (bits 8 to 7 = 01):
// |  |- When "SpecialRealValues" or minus zero are to be encoded (bits 8 to 7 = 01), there shall be
// |  |  |  only one contents octet, with values as follows:
// |  |  |    01000000 - Value is PLUS-INFINITY
// |  |  |    01000001 - Value is MINUS-INFINITY
// |  |  |    01000010 - Value is NOT-A-NUMBER
// |  |  |    01000011 - Value is minus zero
// |  |- All other values having bits 8 and 7 equal to 0 and 1 respectively are reserved for addenda
// |  |  |  to this Recommendation | International Standard.

// MakeReal extracts characteristics, mantissa, and exponent from a float64 value
// Returns:
//   - mantissa: normalized mantissa as int64 (odd for non-zero values)
//   - exponent: unbiased exponent as int
//   - base: encoding base (2 for binary)
func MakeReal(value float64) (mantissa int64, exponent int, base int) {
	// Handle special case: zero
	if value == 0.0 {
		return 0, 0, 2
	}

	// Extract IEEE 754 components from float64
	bits := math.Float64bits(value)

	// Extract sign, exponent, and frac
	var (
		sign = (bits >> 63) & 1
		bexp = int((bits >> 52) & 0x7FF)
		frac = bits & 0xFFFFFFFFFFFFF // 52-bit mantissa
	)
	// Handle special values (infinity, NaN) - let EncodeReal handle these
	if bexp == 0x7FF {
		return 0, 0, 2
	}

	// Handle subnormal numbers (exponent == 0)
	if bexp == 0 {
		// Subnormal: exponent is -1022, mantissa is 0.fraction
		mantissa = int64(frac)
		exponent = -1022 - 52 // Account for 52-bit fraction
	} else {
		// Normal: exponent is biased by 1023, mantissa is 1.fraction
		mantissa = int64((1 << 52) | frac)
		exponent = bexp - 1023 - 52 // Unbias and account for 52-bit fraction
	}

	// Apply sign
	if sign == 1 {
		mantissa = -mantissa
	}

	// Normalize mantissa to be odd (per section 11.3.1)
	// Remove trailing zeros from mantissa
	for mantissa != 0 && mantissa%2 == 0 {
		mantissa = mantissa / 2
		exponent = exponent + 1
	}

	return mantissa, exponent, 2
}

func MakeFloat64(mantissa int64, exponent int, base int) float64 {
	return math.Pow(float64(base), float64(exponent)) * float64(mantissa)
}

// EncodeReal encodes a real value (float64) following PER encoding rules per section 8.5
// Based on pycrate reference implementation using ITU-T X.690 specifications
func (e *Encoder) EncodeReal(value float64) error {
	// Section 8.5.9: Special real values (bits 7-6 = 01, bits 5-0 vary)
	// Per section 15.2, content octets are preceded by an unconstrained length determinant.
	// For these trivial cases (length 0 or 1) we write the length and value directly.
	if math.IsNaN(value) || math.IsInf(value, 0) || (value == 0.0 && math.Signbit(value)) {
		if e.aligned {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}
		// Unconstrained length determinant: single octet, value 1 (bit 8 = 0)
		if err := e.codec.Write(8, 1); err != nil {
			return err
		}
		var octet uint64
		switch {
		case math.IsNaN(value):
			octet = 0x42 // NOT-A-NUMBER
		case math.IsInf(value, 1):
			octet = 0x40 // PLUS-INFINITY
		case math.IsInf(value, -1):
			octet = 0x41 // MINUS-INFINITY
		default:
			octet = 0x43 // Minus zero
		}
		return e.codec.Write(8, octet)
	}

	// Section 8.5.2: Plus zero has no contents octets (length = 0)
	if value == 0.0 {
		if e.aligned {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}
		return e.codec.Write(8, 0) // unconstrained length determinant = 0
	}

	// Section 8.5.7: Binary encoding for non-zero values (base 2)
	// Extract mantissa and exponent from IEEE 754 representation
	mantissa, exponent, base := MakeReal(value)

	// Section 8.5.4-8.5.5: Convert base 10 to base 2 if needed
	// Since 10 = 2 × 5, we have: 10^e = 2^e × 5^e
	// Therefore: m₁₀ × 10^e = (m₁₀ × 5^e) × 2^e
	if base == 10 && exponent != 0 {
		base = 2
		// Calculate 5^|exponent|
		pow5 := int64(math.Pow(5, math.Abs(float64(exponent))))

		// Apply the power of 5 to mantissa
		if exponent > 0 {
			mantissa = mantissa * pow5
		} else {
			mantissa = mantissa / pow5
		}
	}

	// Ensure mantissa is odd (per spec: mantissa = 0 or odd)
	// This normalization ensures canonical encoding
	var sign int64
	if mantissa < 0 {
		sign = -1
		mantissa = -mantissa
	} else {
		sign = 1
	}

	// Right-shift mantissa while it's even, incrementing exponent each time
	// Both mantissa and exponent are modified by this normalization
	for mantissa > 0 && mantissa%2 == 0 {
		mantissa >>= 1
		exponent++
	}

	// Build first octet per section 8.5.6-8.5.7 using temporary bitbuffer
	// Bit 7: Binary encoding flag (1 for binary, 0 for decimal)
	// Bit 6: Sign bit S (1 if negative, 0 if positive)
	// Bits 5-4: Base B (00=base2, 01=base8, 10=base16)
	// Bits 3-2: Scaling factor F (always 0 in normalized form)
	// Bits 1-0: Exponent format (0=1 octet, 1=2 octets, 2=3 octets, 3=length prefix)
	temp := bitbuffer.CreateWriter()

	// Write Bit 7: Binary encoding flag (always 1)
	temp.Write(1, 1)

	// Write Bit 6: Sign bit
	if sign < 0 {
		temp.Write(1, 1)
	} else {
		temp.Write(1, 0)
	}

	// Write Bits 5-4: Base (always 00 for base 2)
	temp.Write(2, 0)

	// Write Bits 3-2: Scaling factor (always 00 for normalized form)
	temp.Write(2, 0)

	{
		// Calculate exponent length in octets for first octet encoding
		// Per Python reference: int_bytelen() returns minimum bytes needed
		// Calculate exponent length using math and bits packages
		length := OctetsTwosComplementBinaryInteger(int64(exponent))
		// Write Bits 1-0: Exponent format (actualExpLen-1, capped at 3 for length prefix)
		if length > 3 {
			temp.Write(2, 3)
		} else {
			temp.Write(2, uint64(length-1))
		}

		// Encode exponent based on length format
		switch length {
		case 1:
			// Single octet: encode as signed byte
			temp.Write(8, uint64(int8(exponent)))
		case 2:
			// Two octets: encode as signed big-endian short
			temp.Write(16, uint64(int16(exponent)))
		case 3:
			// Three octets: encode as signed big-endian (three bytes)
			if exponent < 0 {
				// Two's complement for negative values
				temp.Write(24, uint64((1<<24)+exponent))
			} else {
				temp.Write(24, uint64(exponent))
			}
		default:
			// Length prefix format: length octet followed by exponent octets
			temp.Write(8, uint64(length))

			// Encode exponent in actualExpLen octets as two's complement
			if exponent < 0 {
				temp.Write(uint8(length*8), uint64((1<<uint(length*8))+exponent))
			} else {
				temp.Write(uint8(length*8), uint64(exponent))
			}
		}
	}

	// Encode mantissa N as unsigned binary integer
	// Convert mantissa to bytes (big-endian, minimum length)
	if mantissa > 0 {
		length := (bits.Len64(uint64(mantissa)) + 7) / 8
		temp.Write(uint8(length*8), uint64(mantissa))
	}

	// Encode the contents with length determinant per section 11.9
	return e.EncodeOctetString(temp.Bytes(), nil, nil, false)
}

// 16 Encoding the bitstring type
// |- NOTE - (Tutorial) Bitstrings constrained to a fixed length less than or equal to 16
// |  |  bits do not cause octet alignment.
// |  |  Larger bitstrings are octet-aligned in the ALIGNED variant.
// |  |  If the length is fixed by constraints and the upper bound is less than 64K, there
// |  |  is no explicit length encoding, otherwise a length encoding is included which can
// |  |  take any of the forms specified earlier for length encodings, including
// |  |  fragmentation for large bit strings.
// |- 16.1 PER-visible constraints can only constrain the length of the bitstring.
// |- 16.2 Where there are no PER-visible constraints and Rec. ITU-T X.680 |
// |  |  ISO/IEC 8824-1, 22.7, applies the value shall be encoded with no trailing 0 bits
// |  |  (note that this means that a value with no 1 bits is always encoded as an empty
// |  |  bit string).
// |- 16.3 Where there is a PER-visible constraint and Rec. ITU-T X.680 | ISO/IEC 8824-1,
// |  |  22.7, applies (i.e., the bitstring type is defined with a "NamedBitList"), the
// |  |  value shall be encoded with trailing 0 bits added or removed as necessary to ensure
// |  |  that the size of the transmitted value is the smallest size capable of carrying
// |  |  this value and satisfies the effective size constraint.
// |- 16.4 Let the maximum number of bits in the bitstring (as determined by PER-visible
// |  |  constraints on the length) be "ub" and the minimum number of bits be "lb".
// |  |  If there is no finite maximum we say that "ub" is unset.
// |  |  If there is no constraint on the minimum, then "lb" has the value zero.
// |  |  Let the length of the actual bit string value to be encoded be "n" bits.
// |- 16.5 When a bitstring value is placed in a bit-field as specified in 16.6 to 16.11,
// |  |  the leading bit of the bitstring value shall be placed in the leading bit of the
// |  |  bit-field, and the trailing bit of the bitstring value shall be placed in the
// |  |  trailing bit of the bit-field.
// |- 16.6 If the type is extensible for PER encodings (see 10.3.9), then a bit-field
// |  |  consisting of a single bit shall be added to the field-list.
// |  |  The bit shall be set to 1 if the length of this encoding is not within the range of
// |  |  the extension root, and zero otherwise.
// |  |  In the former case, 16.11 shall be invoked to add the length as a
// |  |  semi-constrained whole number to the field-list, followed by the bitstring value.
// |  |  In the latter case the length and value shall be encoded as if no extension is
// |  |  present in the constraint.
// |- 16.7 If an extension marker is not present in the constraint specification of the
// |  |  bitstring type, then 16.8 to 16.11 apply.
// |- 16.8 If the bitstring is constrained to be of zero length ("ub" equals zero), then
// |  |  it shall not be encoded (no additions to the field-list), completing the
// |  |  procedures of this clause.
// |- 16.9 If all values of the bitstring are constrained to be of the same length ("ub"
// |  |  equals "lb") and that length is less than or equal to sixteen bits, then the
// |  |  bitstring shall be placed in a bit-field of the constrained length "ub" which shall
// |  |  be appended to the field-list with no length determinant, completing the procedures
// |  |  of this clause.
// |- 16.10 If all values of the bitstring are constrained to be of the same length ("ub"
// |  |  equals "lb") and that length is greater than sixteen bits but less than 64K bits,
// |  |  then the bitstring shall be placed in a bit-field (octet-aligned in the ALIGNED
// |  |  variant) of length "ub" (which is not necessarily a multiple of eight bits) and
// |  |  shall be appended to the field-list with no length determinant, completing the
// |  |  procedures of this clause.
// |- 16.11 If 16.8-16.10 do not apply, the bitstring shall be placed in a bit-field
// |  |  (octet-aligned in the ALIGNED variant) of length "n" bits and the procedures of
// |  |  11.9 shall be invoked to add this bit-field (octet-aligned in the ALIGNED variant)
// |  |  of "n" bits to the field-list, preceded by a length determinant equal to "n" bits
// |  |  as a constrained whole number if "ub" is set and is less than 64K or as a
// |  |  semi-constrained whole number if "ub" is unset.
// |  |  "lb" is as determined above.
// |  |- NOTE - Fragmentation applies for unconstrained or large "ub" after 16K, 32K, 48K
// |  |  |  or 64K bits.

func (e *Encoder) WriteBits(data []byte, count uint) error {
	if count == 0 {
		return nil
	}

	num := count / 8
	if num > 0 {
		if err := e.codec.WriteBytes(data[:num]); err != nil {
			return err
		}
	}

	remaining := count % 8
	if remaining > 0 {
		var (
			last  = data[num]
			value = uint64(last >> (8 - remaining))
		)
		return e.codec.Write(uint8(remaining), value)
	}
	return nil
}

func (e *Encoder) EncodeBitString(value *asn1.BitString, lb *uint64,
	ub *uint64, extensible bool) error {
	// 16.6 If the type is extensible, add a bit indicating if the length is in
	// the extension root
	if extensible {
		extended := false
		if lb != nil && uint64(value.BitLength) < *lb {
			extended = true
		}
		if ub != nil && uint64(value.BitLength) > *ub {
			extended = true
		}

		if extended {
			if err := e.codec.Write(1, 1); err != nil {
				return err
			}
			// Encode length as semi-constrained whole number (16.11) with
			// fragmentation
			zero := uint64(0)
			if err := e.EncodeBitStringFragments(value.Bytes,
				uint64(value.BitLength), &zero, nil); err != nil {
				return err
			}
			return nil
		} else {
			if err := e.codec.Write(1, 0); err != nil {
				return err
			}
		}
	}

	// 16.8 If constrained to zero length, no encoding
	if ub != nil && *ub == 0 {
		return nil
	}

	// 16.9 If fixed length <= 16 bits, place in bit-field (no length
	// determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub <= 16 {
		return e.WriteBits(value.Bytes, uint(*ub))
	}

	// 16.10 If fixed length > 16 bits but < 64K, place in bit-field
	// octet-aligned (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub < 65536 {
		if e.aligned {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}
		return e.WriteBits(value.Bytes, uint(*ub))
	}

	// 16.11 Otherwise, encode with length determinant (with fragmentation
	// support)
	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}
	return e.EncodeBitStringFragments(value.Bytes, uint64(value.BitLength),
		lb, ub)
}

func (e *Encoder) EncodeBitStringFragments(value []byte, count uint64,
	lb *uint64, ub *uint64) error {
	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	// Handle empty value: still need to encode length determinant of 0
	if count == 0 {
		_, err := e.EncodeLengthDeterminant(0, lb, ub)
		return err
	}

	offset := uint64(0)

	// Encode with length determinant and handle fragmentation
	for offset < count {
		remaining := count - offset
		pending, err := e.EncodeLengthDeterminant(remaining, lb, ub)
		if err != nil {
			return err
		}

		// Determine how much to encode in this fragment
		var length uint64
		if pending == 0 {
			// No pending length - encode everything remaining
			length = remaining
		} else {
			// Fragmented - encode only what was encoded by length determinant
			length = remaining - pending
		}

		// Write the fragment data
		nbytes := offset / 8
		if err := e.WriteBits(value[nbytes:], uint(length)); err != nil {
			return err
		}

		offset = offset + length

		// If no pending length, we're done
		if pending == 0 {
			break
		}
	}

	return nil
}

// 17 Encoding the octetstring type
// |- NOTE - Octet strings of fixed length less than or equal to two octets are not
// |  |  octet-aligned.
// |  |  All other octet strings are octet-aligned in the ALIGNED variant.
// |  |  Fixed length octet strings encode with no length octets if they are shorter than
// |  |  64K.
// |  |  For unconstrained octet strings the length is explicitly encoded (with
// |  |  fragmentation if necessary).
// |- 17.1 PER-visible constraints can only constrain the length of the octetstring.
// |- 17.2 Let the maximum number of octets in the octetstring (as determined by
// |  |  PER-visible constraints on the length) be "ub" and the minimum number of octets be
// |  |  "lb".
// |  |  If there is no finite maximum, we say that "ub" is unset.
// |  |  If there is no constraint on the minimum, then "lb" has the value zero.
// |  |  Let the length of the actual octetstring value to be encoded be "n" octets.
// |- 17.3 If the type is extensible for PER encodings (see 10.3.9), then a bit-field
// |  |  consisting of a single bit shall be added to the field-list.
// |  |  The bit shall be set to 1 if the length of this encoding is not within the range of
// |  |  the extension root, and zero otherwise.
// |  |  In the former case 17.8 shall be invoked to add the length as a
// |  |  semi-constrained whole number to the field-list, followed by the octetstring value.
// |  |  In the latter case the length and value shall be encoded as if no extension is
// |  |  present in the constraint.
// |- 17.4 If an extension marker is not present in the constraint specification of the
// |  |  octetstring type, then 17.5 to 17.8 apply.
// |- 17.5 If the octetstring is constrained to be of zero length ("ub" equals zero), then
// |  |  it shall not be encoded (no additions to the field-list), completing the
// |  |  procedures of this clause.
// |- 17.6 If all values of the octetstring are constrained to be of the same length ("ub"
// |  |  equals "lb") and that length is less than or equal to two octets, the octetstring
// |  |  shall be placed in a bit-field with a number of bits equal to the constrained length
// |  |  "ub" multiplied by eight which shall be appended to the field-list with no length
// |  |  determinant, completing the procedures of this clause.
// |- 17.7 If all values of the octetstring are constrained to be of the same length ("ub"
// |  |  equals "lb") and that length is greater than two octets but less than 64K, then
// |  |  the octetstring shall be placed in a bit-field (octet-aligned in the ALIGNED
// |  |  variant) with the constrained length "ub" octets which shall be appended to the
// |  |  field-list with no length determinant, completing the procedures of this clause.
// |- 17.8 If 17.5 to 17.7 do not apply, the octetstring shall be placed in a bit-field
// |  |  (octet-aligned in the ALIGNED variant) of length "n" octets and the procedures of
// |  |  11.9 shall be invoked to add this bit-field (octet-aligned in the ALIGNED variant)
// |  |  of "n" octets to the field-list, preceded by a length determinant equal to "n"
// |  |  octets as a constrained whole number if "ub" is set, and as a semi-constrained
// |  |  whole number if "ub" is unset.
// |  |  "lb" is as determined above.
// |  |- NOTE - The fragmentation procedures may apply after 16K, 32K, 48K, or 64K octets.

func (e *Encoder) EncodeOctetString(value []byte, lb *uint64, ub *uint64, extensible bool) error {
	n := uint64(len(value))

	// 17.3 If extensible, add a bit indicating if the length is in the extension root
	if extensible {
		extended := false
		if lb != nil && n < *lb {
			extended = true
		}
		if ub != nil && n > *ub {
			extended = true
		}

		if extended {
			if err := e.codec.Write(1, 1); err != nil {
				return err
			}
			// Encode length as semi-constrained whole number (17.8) with fragmentation
			zero := uint64(0)
			return e.EncodeOctetStringFragments(value, &zero, nil)
		} else {
			if err := e.codec.Write(1, 0); err != nil {
				return err
			}
		}
	}

	// 17.5 If constrained to zero length, no encoding
	if ub != nil && *ub == 0 {
		return nil
	}

	// 17.6 If fixed length <= 2 octets, place in bit-field (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub <= 2 {
		return e.codec.WriteBytes(value)
	}

	// 17.7 If fixed length > 2 octets but < 64K, place in bit-field octet-aligned
	// (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub < 65536 {
		if e.aligned {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}
		return e.codec.WriteBytes(value)
	}

	// 17.8 Otherwise, encode with length determinant (with fragmentation support)
	return e.EncodeOctetStringFragments(value, lb, ub)
}

// EncodeOctetStringFragments encodes an octet string with length determinant,
// supporting fragmentation for lengths >= 16K per section 11.9.3.8
func (e *Encoder) EncodeOctetStringFragments(value []byte, lb *uint64, ub *uint64) error {
	if e.aligned {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	n := uint64(len(value))

	// Handle empty value: still need to encode length determinant of 0
	if n == 0 {
		_, err := e.EncodeLengthDeterminant(0, lb, ub)
		return err
	}

	offset := uint64(0)

	// Encode with length determinant and handle fragmentation
	for offset < n {
		remaining := n - offset
		pending, err := e.EncodeLengthDeterminant(remaining, lb, ub)
		if err != nil {
			return err
		}

		// Determine how much to encode in this fragment
		var length uint64
		if pending == 0 {
			// No pending length - encode everything remaining
			length = remaining
		} else {
			// Fragmented - encode only what was encoded by length determinant
			length = remaining - pending
		}

		// Write the fragment data
		if err := e.codec.WriteBytes(value[offset : offset+length]); err != nil {
			return err
		}

		offset += length

		// If no pending length, we're done
		if pending == 0 {
			break
		}
	}

	return nil
}

// 18 Encoding the null type
// |- NOTE - (Tutorial) The null type is essentially a place holder, with practical meaning
// |  |  only in the case of a choice or an optional set or sequence component.
// |  |  Identification of the null in a choice, or its presence as an optional element, is
// |  |  performed in these encoding rules without the need to have octets representing the
// |  |  null.
// |  |  Null values therefore never contribute to the octets of an encoding.
// |  |  There shall be no addition to the field-list for a null value.

func (e *Encoder) EncodeNull() error {
	return nil
}

// 24 Encoding the object identifier type
// |- NOTE - (Tutorial) An object identifier type encoding uses the contents octets of BER preceded by a length determinant that will
// |  |  in practice be a single octet.
// |  |  The encoding specified for BER shall be applied to give a bit-field (octet-aligned in the ALIGNED variant) which is the
// |  |  contents octets of the BER encoding. The contents octets of this BER encoding consists of "n" (say) octets and is placed
// |  |  in a bit-field (octet-aligned in the ALIGNED variant) of "n" octets. The procedures of 11.9 shall be invoked to append
// |  |  this bit-field (octet-aligned in the ALIGNED variant) to the field-list, preceded by a length determinant equal to "n" as a
// |  |  semi-constrained whole number octet count.

// EncodeObjectIdentifier encodes an OBJECT IDENTIFIER value per section 24 of ITU-T X.691.
// The OID is encoded as an octet string containing the DER value octets.
func (e *Encoder) EncodeObjectIdentifier(oid asn1.ObjectIdentifier) error {
	// Marshal the OID to DER encoding using Go's encoding/asn1 package
	// DER format: tag (0x06) + length + value octets
	data, err := asn1.Marshal(oid)
	if err != nil {
		return err
	}

	// Extract value octets by parsing the DER structure
	if data[1]&0x80 == 0 {
		// Short form: length in low 7 bits
		data = data[2:]
	} else {
		// Long form: next (data[1] & 0x7f) bytes contain the length
		data = data[2+int(data[1]&0x7f):]
	}

	// Encode the value octets as an unconstrained octet string
	return e.EncodeOctetString(data, nil, nil, false)
}

// 25 Encoding the relative object identifier type
// |- NOTE - (Tutorial) A relative object identifier type encoding uses the contents octets of BER preceded by a length determinant that
// |  |  will in practice be a single octet. The following text is identical to that of clause 24.
// |  |  The encoding specified for BER shall be applied to give a bit-field (octet-aligned in the ALIGNED variant) which is the
// |  |  contents octets of the BER encoding. The contents octets of this BER encoding consists of "n" (say) octets and is placed
// |  |  in a bit-field (octet-aligned in the ALIGNED variant) of "n" octets. The procedures of 11.9 shall be invoked to append
// |  |  this bit-field (octet-aligned in the ALIGNED variant) to the field-list, preceded by a length determinant equal to "n" as a
// |  |  semi-constrained whole number octet count.

// 30 Encoding the restricted character string types
// |- NOTE 1 - (Tutorial ALIGNED variant) Character strings of fixed length less than or equal
// |  |  to two octets are not octet-aligned. Character strings of variable length that are
// |  |  constrained to have a maximum length of less than two octets are not octet-aligned. All
// |  |  other character strings are octet-aligned in the ALIGNED variant. Fixed length character
// |  |  strings encode with no length octets if they are shorter than 64K characters. For
// |  |  unconstrained character strings or constrained character strings longer than 64K-1, the
// |  |  length is explicitly encoded (with fragmentation if necessary). Each NumericString,
// |  |  PrintableString, VisibleString (ISO646String), IA5String, BMPString and UniversalString
// |  |  character is encoded into the number of bits that is the smallest power of two that can
// |  |  accommodate all characters allowed by the effective permitted-alphabet constraint.
// |- NOTE 2 - (Tutorial UNALIGNED variant) Character strings are not octet-aligned. If there
// |  |  is only one possible length value there is no length encoding if they are shorter than
// |  |  64K characters. For unconstrained character strings or constrained character strings
// |  |  longer than 64K-1, the length is explicitly encoded (with fragmentation if necessary).
// |  |  Each NumericString, PrintableString, VisibleString (ISO646String), IA5String, BMPString
// |  |  and UniversalString character is encoded into the number of bits that is the smallest
// |  |  that can accommodate all characters allowed by the effective permitted-alphabet
// |  |  constraint.
// |- NOTE 3 - (Tutorial on size of each encoded character) Encoding of each character depends
// |  |  on the effective permitted-alphabet constraint (see 10.3.12), which defines the alphabet
// |  |  in use for the type. Suppose this alphabet consists of a set of characters ALPHA (say).
// |  |  For each of the known-multiplier character string types (see 3.7.16), there is an
// |  |  integer value associated with each character, obtained by reference to some code table
// |  |  associated with the restricted character string type. The set of values BETA (say)
// |  |  corresponding to the set of characters ALPHA is used to determine the encoding to be
// |  |  used, as follows: the number of bits for the encoding of each character is determined
// |  |  solely by the number of elements, N, in the set BETA (or ALPHA). For the UNALIGNED
// |  |  variant is the smallest number of bits that can encode the value N - 1 as a non-negative
// |  |  binary integer. For the ALIGNED variant this is the smallest number of bits that is a
// |  |  power of two and that can encode the value N - 1. Suppose the selected number of bits
// |  |  is B. Then if every value in the set BETA can be encoded (with no transformation) in B
// |  |  bits, then the value in set BETA is used to represent the corresponding characters in
// |  |  the set ALPHA. Otherwise, the values in set BETA are taken in ascending order and
// |  |  replaced by values 0, 1, 2, and so on up to N - 1, and it is these values that are used
// |  |  to represent the corresponding character. In summary: minimum bits (taken to the next
// |  |  power of two for the ALIGNED variant) are always used. Preference is then given to using
// |  |  the value normally associated with the character, but if any of these values cannot be
// |  |  encoded in the minimum number of bits a compaction is applied. The following restricted
// |  |  character string types are known-multiplier character string types: NumericString,
// |  |  PrintableString, VisibleString (ISO646String), IA5String, BMPString, and UniversalString.
// |  |  Effective permitted-alphabet constraints are PER-visible only for these types.
// |- 30.1 The effective size constraint notation may determine an upper bound "aub" for the
// |  |  length of the abstract character string. Otherwise, "aub" is unset.
// |- 30.2 The effective size constraint notation may determine a non-zero lower bound "alb"
// |  |  for the length of the abstract character string. Otherwise, "alb" is zero.
// |  |- NOTE - PER-visible constraints only apply to known-multiplier character string types.
// |  |  For other restricted character string types "aub" will be unset and "alb" will be zero.
// |- 30.3 If the type is extensible for PER encodings (see 10.3.18), then a bit-field
// |  |  consisting of a single bit shall be added to the field-list. The single bit shall be set
// |  |  to zero if the value is within the range of the extension root, and to one otherwise. If
// |  |  the value is outside the range of the extension root, then the following encoding shall be
// |  |  as if there was no effective size constraint, and shall have the effective
// |  |  permitted-alphabet constraint specified in 10.3.12.
// |  |- NOTE 1 - Only the known-multiplier character string types can be extensible for PER
// |  |  encodings. Extensibility markers on other character string types do not affect the PER
// |  |  encoding.
// |  |- NOTE 2 - Effective permitted-alphabet constraints can never be extensible, as
// |  |  extensible permitted-alphabet constraints are not PER-visible (see 10.3.11).
// |- 30.4 This subclause applies to known-multiplier character strings. Encoding of the other
// |  |  restricted character string types is specified in 30.5.
// |  |- 30.4.1 The effective permitted alphabet is defined to be that alphabet permitted by
// |  |  |  the permitted-alphabet constraint, or the entire alphabet of the built-in type if there
// |  |  |  is no PermittedAlphabet constraint.
// |  |- 30.4.2 Let N be the number of characters in the effective permitted alphabet. Let B be
// |  |  |  the smallest integer such that 2 to the power B is greater than or equal to N. Let B2 be
// |  |  |  the smallest power of 2 that is greater than or equal to B. Then in the ALIGNED variant,
// |  |  |  each character shall encode into B2 bits, and in the UNALIGNED variant into B bits. Let
// |  |  |  the number of bits identified by this rule be "b".
// |  |- 30.4.3 A numerical value "v" is associated with each character by reference to Rec.
// |  |  |  ITU-T X.680 | ISO/IEC 8824-1, clause 43 as follows. For UniversalString, the value is
// |  |  |  that used to determine the canonical order in Rec. ITU-T X.680 | ISO/IEC 8824-1, 43.3
// |  |  |  (the value is in the range 0 to 232 - 1). For BMPString, the value is that used to
// |  |  |  determine the canonical order in Rec. ITU-T X.680 | ISO/IEC 8824-1, 43.3 (the value is
// |  |  |  in the range 0 to 216 - 1). For NumericString and PrintableString and VisibleString
// |  |  |  and IA5String the value is that defined for the ISO/IEC 646 encoding of the
// |  |  |  corresponding character. (For IA5String the range is 0 to 127, for VisibleString it is
// |  |  |  32 to 126, for NumericString it is 32 to 57, and for PrintableString it is 32 to 122.
// |  |  |  For IA5String and VisibleString all values in the range are present, but for
// |  |  |  NumericString and PrintableString not all values in the range are in use.)
// |  |- 30.4.4 Let the smallest value in the range for the set of characters in the permitted
// |  |  |  alphabet be "lb" and the largest value be "ub". Then the encoding of a character into
// |  |  |  "b" bits is the non-negative-binary-integer encoding of the value "v" identified as
// |  |  |  follows: a) if "ub" is less than or equal to 2b - 1, then "v" is the value specified in
// |  |  |  above; otherwise b) the characters are placed in the canonical order defined in Rec.
// |  |  |  ITU-T X.680 | ISO/IEC 8824-1, clause 43. The first is assigned the value zero and the
// |  |  |  next in canonical order is assigned a value that is one greater than the value assigned
// |  |  |  to the previous character in the canonical order. These are the values "v". NOTE - Item
// |  |  |  a) above can never apply to a constrained or unconstrained NumericString character,
// |  |  |  which always encodes into four bits or less using b).
// |  |- 30.4.5 The encoding of the entire character string shall be obtained by encoding each
// |  |  |  character (using an appropriate value "v") as a non-negative-binary-integer into "b"
// |  |  |  bits which shall be concatenated to form a bit-field that is a multiple of "b" bits.
// |  |- 30.4.6 If "aub" equals "alb" and is less than 64K, then the bit-field shall be added
// |  |  |  to the field-list as a field (octet-aligned in the ALIGNED variant) if "aub" times "b"
// |  |  |  is greater than 16, but shall otherwise be added as a bit-field that is not
// |  |  |  octet-aligned. This completes the procedures of this subclause.
// |  |- 30.4.7 If "aub" does not equal "alb" or is greater than or equal to 64K, then 11.9
// |  |  |  shall be invoked to add the bit-field preceded by a length determinant with "n" as a
// |  |  |  count of the characters in the character string with a lower bound for the length
// |  |  |  determinant of "alb" and an upper bound of "aub". The bit-field shall be added as a
// |  |  |  field (octet-aligned in the ALIGNED variant) if "aub" times "b" is greater than or equal
// |  |  |  to 16, but shall otherwise be added as a bit-field that is not octet-aligned. This
// |  |  |  completes the procedures of this subclause. NOTE - Both 30.4.6 and 30.4.7 specify no
// |  |  |  alignment if "aub" times "b" is less than 16, and alignment if the product is greater
// |  |  |  than 16. For a value exactly equal to 16, 30.4.6 specifies no alignment and 30.4.7
// |  |  |  specifies alignment.
// |- 30.5 This subclause applies to character strings that are not known-multiplier character
// |  |  |  strings. In this case, constraints are never PER-visible, and the type can never be
// |  |  |  extensible for PER encoding.
// |  |- 30.5.1 For BASIC-PER, reference below to "base encoding" means production of the
// |  |  |  octet string specified in Rec. ITU-T X.690 | ISO/IEC 8825-1, 8.23.5. For CANONICAL-PER
// |  |  |  it means the production of the same octet string subject to the restrictions specified
// |  |  |  for CER and DER in Rec. ITU-T X.690 | ISO/IEC 8825-1, 11.4.
// |  |- 30.5.2 The "base encoding" shall be applied to the character string to give a field of
// |  |  |  "n" octets.
// |  |- 30.5.3 Subclause 11.9 shall be invoked to add the field of "n" octets as a bit-field
// |  |  |  (octet-aligned in the ALIGNED variant), preceded by an unconstrained length determinant
// |  |  |  with "n" as a count in octets, completing the procedures of this subclause.

// 31 Encoding the unrestricted character string type
// |- 31.1 There are two ways in which an unrestricted character string type can be encoded:
// |  |  a) the syntaxes alternative of the unrestricted character string type is constrained
// |  |  with a PER-visible inner type constraint to a single value or identification is
// |  |  constrained with a PER-visible inner type constraint to the fixed alternative, in which
// |  |  case only the string-value shall be encoded; this is called the "predefined" case; b) an
// |  |  inner type constraint is not employed to constrain the syntaxes alternative to a single
// |  |  value, nor to constrain identification to the fixed alternative, in which case both the
// |  |  identification and string-value shall be encoded; this is called the "general" case.
// |- 31.2 For the "predefined" case, the encoding of the value of the CHARACTER STRING type
// |  |  shall be the PER-encoding of a value of the OCTET STRING type. The value of the OCTET
// |  |  STRING shall be the octets which form the complete encoding of the character string
// |  |  value referenced in Rec. ITU-T X.680 | ISO/IEC 8824-1, 44.3 a).
// |- 31.3 In the "general" case, the encoding of a value of the unrestricted character string
// |  |  type shall be the PER encoding of the type defined in Rec. ITU-T X.680 | ISO/IEC
// |  |  8824-1, 44.5, with the data-value-descriptor component removed (that is, there shall be
// |  |  no OPTIONAL bit-map at the head of the encoding of the SEQUENCE). The value of the
// |  |  string-value component of type OCTET STRING shall be the octets which form the complete
// |  |  encoding of the character string value referenced in Rec. ITU-T X.680 | ISO/IEC 8824-1,
// |  |  44.3 a).

func (e *Encoder) EncodeString(value string, lb *uint64, ub *uint64, extensible bool) error {
	// This is suitable for restricted character string types that use a full byte (or more)
	// per character in their native encoding, where PER treats the value as an opaque
	// octet string with no per-character bit optimization:
	//   - VisibleString    (ISO 646, 1 byte/char, unconstrained alphabet)
	//   - IA5String        (ISO 646, 1 byte/char, unconstrained alphabet)
	//   - PrintableString  (ISO 646 subset, 1 byte/char, unconstrained alphabet)
	return e.EncodeOctetString(unsafe.Slice(unsafe.StringData(value), len(value)), lb, ub, extensible)
}

// TODO - EncodeNumericString (section 30.4) - known-multiplier character string
// Input: string, lb, ub, extensible
// Implements per-character bit-packing with 4 bits per character for permitted alphabet

// TODO - EncodeBMPString (section 30.4) - known-multiplier character string
// Input: string, lb, ub, extensible
// Implements per-character bit-packing with 16 bits per character for UCS-2 alphabet

// TODO - EncodeUniversalString (section 30.4) - known-multiplier character string
// Input: string, lb, ub, extensible
// Implements per-character bit-packing with 32 bits per character for UCS-4 alphabet

// TODO - EncodeTeletexString (section 30.5) - non-known-multiplier character string
// Input: []byte, lb, ub, extensible
// Requires BER encoding as intermediate step per X.690 8.23.5

// TODO - EncodeVideotexString (section 30.5) - non-known-multiplier character string
// Input: []byte, lb, ub, extensible
// Requires BER encoding as intermediate step per X.690 8.23.5

// TODO - EncodeGraphicString (section 30.5) - non-known-multiplier character string
// Input: []byte, lb, ub, extensible
// Requires BER encoding as intermediate step per X.690 8.23.5

// TODO - EncodeGeneralString (section 30.5) - non-known-multiplier character string
// Input: []byte, lb, ub, extensible
// Requires BER encoding as intermediate step per X.690 8.23.5

// TODO - EncodeUnrestrictedCharacterString (section 31) - unrestricted character string
// Per ITU-T X.680 clause 44, the CHARACTER STRING type is:
//
//   CHARACTER STRING ::= SEQUENCE {
//       identification Identification,
//       string-value   OCTET STRING
//   }
//
// Where Identification is a CHOICE with the following alternatives:
//   Identification ::= CHOICE {
//       syntaxes [0]            SEQUENCE { abstract PrintableString,
//                                          transfer PrintableString },
//       syntax [1]              OBJECT IDENTIFIER,
//       presentation-context-id [2] INTEGER,
//       context-negotiation [3] SEQUENCE { presentation-context-id INTEGER,
//                                          transfer-syntax OBJECT IDENTIFIER },
//       transfer-syntax [4]     OBJECT IDENTIFIER,
//       fixed [5]               NULL
//   }
//
// Input: struct with identification (CHOICE) and string-value (OCTET STRING)
// Requires PER encoding of SEQUENCE type per X.680 44.5 (data-value-descriptor removed)

// 19 Encoding the sequence type
// |- NOTE - (Tutorial) A sequence type begins with a preamble which is a bit-map. If the
// |  |  sequence type has no extension marker, then the bit-map merely records the presence
// |  |  or absence of default and optional components in the type, encoded as a fixed length
// |  |  bit-field. If the sequence type does have an extension marker, then the bit-map is
// |  |  preceded by a single bit that says whether values of extension additions are actually
// |  |  present in the encoding. The preamble is encoded without any length determinant
// |  |  provided it is less than 64K bits long, otherwise a length determinant is encoded to
// |  |  obtain fragmentation. The preamble is followed by the fields that encode each of the
// |  |  components, taken in turn. If there are extension additions, then immediately before
// |  |  the first one is encoded there is the encoding (as a normally small length) of a count
// |  |  of the number of extension additions in the type being encoded, followed by a bit-map
// |  |  equal in length to this count which records the presence or absence of values of each
// |  |  extension addition. This is followed by the encodings of the extension additions as if
// |  |  each one was the value of an open type field.
// |- 19.1 If the sequence type has an extension marker in the "ComponentTypeLists" or in the
// |  |  "SequenceType" productions, then a single bit shall first be added to the field-list in
// |  |  a bit-field of length one. The bit shall be one if values of extension additions are
// |  |  present in this encoding, and zero otherwise. (This bit is called the "extension bit" in
// |  |  the following text.) If there is no extension marker in the "ComponentTypeLists" or in
// |  |  the "SequenceType" productions, there shall be no extension bit added.
// |- 19.2 If the sequence type has "n" components in the extension root that are marked
// |  |  OPTIONAL or DEFAULT, then a single bit-field with "n" bits shall be produced for
// |  |  addition to the field-list. The bits of the bit-field shall, taken in order, encode
// |  |  the presence or absence of an encoding of each optional or default component in the
// |  |  sequence type. A bit value of 1 shall encode the presence of the encoding of the
// |  |  component, and a bit value of 0 shall encode the absence of the encoding of the
// |  |  component. The leading bit in the preamble shall encode the presence or absence of the
// |  |  first optional or default component, and the trailing bit shall encode the presence or
// |  |  absence of the last optional or default component.
// |- 19.3 If "n" is less than 64K, the bit-field shall be appended to the field-list. If "n"
// |  |  is greater than or equal to 64K, then the procedures of 11.9 shall be invoked to add
// |  |  this bit-field of "n" bits to the field-list, preceded by a length determinant equal
// |  |  to "n" bits as a constrained whole number with "ub" and "lb" both set to "n".
// |  |- NOTE - In this case, "ub" and "lb" will be ignored by the length procedures. These
// |  |  |  procedures are invoked here in order to provide fragmentation of a large preamble.
// |  |  |  The situation is expected to arise only rarely.
// |- 19.4 The preamble shall be followed by the field-lists of each of the components of the
// |  |  sequence value which are present, taken in turn.
// |- 19.5 For CANONICAL-PER, encodings of components marked DEFAULT shall always be absent if
// |  |  the value to be encoded is the default value. For BASIC-PER, encodings of components
// |  |  marked DEFAULT shall always be absent if the value to be encoded is the default value
// |  |  of a simple type (see 3.7.25), otherwise it is a sender's option whether or not to
// |  |  encode it.
// |- 19.6 This completes the encoding if the extension bit is absent or is zero. If the
// |  |  extension bit is present and set to one, then the following procedures apply.
// |- 19.7 Let the number of extension additions in the type being encoded be "n", then a
// |  |  bit-field with "n" bits shall be produced for addition to the field-list. The bits of
// |  |  the bit-field shall, taken in order, encode the presence or absence of an encoding of
// |  |  each extension addition in the type being encoded. A bit value of 1 shall encode the
// |  |  presence of the encoding of the extension addition, and a bit value of 0 shall encode
// |  |  the absence of the encoding of the extension addition. The leading bit in the bit-field
// |  |  shall encode the presence or absence of the first extension addition, and the trailing
// |  |  bit shall encode the presence or absence of the last extension addition.
// |  |- NOTE - If conformance is claimed to a particular version of a specification, then the
// |  |  |  value "n" is always equal to the number of extension additions in that version.
// |- 19.8 The procedures of 11.9 shall be invoked to add this bit-field of "n" bits to the
// |  |  field-list, preceded by a length determinant equal to "n" as a normally small length.
// |  |- NOTE - "n" cannot be zero, as this procedure is only invoked if there is at least one
// |  |  |  extension addition being encoded.
// |- 19.9 This shall be followed by field-lists containing the encodings of each extension
// |  |  addition that is present, taken in turn. Each extension addition that is a
// |  |  "ComponentType" (i.e., not an "ExtensionAdditionGroup") shall be encoded as if it were
// |  |  the value of an open type field as specified in 11.2.1. Each extension addition that
// |  |  is an "ExtensionAdditionGroup" shall be encoded as a sequence type as specified in
// |  |  19.2 to 19.6, which is then encoded as if it were the value of an open type field as
// |  |  specified in 11.2.1. If all components values of the "ExtensionAdditionGroup" are
// |  |  missing then, the "ExtensionAdditionGroup" shall be encoded as a missing extension
// |  |  addition (i.e., the corresponding bit in the bit-field described in 19.7 shall be set
// |  |  to 0).
// |  |- NOTE 1 - If an "ExtensionAdditionGroup" contains components marked OPTIONAL or
// |  |  |  DEFAULT, then the "ExtensionAdditionGroup" is prefixed with a bit-map that indicates
// |  |  |  the presence/absence of values for each component marked OPTIONAL or DEFAULT.
// |  |- NOTE 2 - "RootComponentTypeList" components that are defined after the extension
// |  |  |  marker pair are encoded as if they were defined immediately before the extension
// |  |  |  marker pair.

// 20 Encoding the sequence-of type
// |- 20.1 PER-visible constraints can constrain the number of components of the sequence-of
// |  |  type.
// |- 20.2 Let the maximum number of components in the sequence-of (as determined by
// |  |  PER-visible constraints) be "ub" components and the minimum number of components be
// |  |  "lb". If there is no finite maximum or "ub" is greater than or equal to 64K we say
// |  |  that "ub" is unset. If there is no constraint on the minimum, then "lb" has the value
// |  |  zero. Let the number of components in the actual sequence-of value to be encoded be
// |  |  "n" components.
// |- 20.3 The encoding of each component of the sequence-of will generate a number of fields
// |  |  to be appended to the field-list for the sequence-of type.
// |- 20.4 If there is a PER-visible constraint and an extension marker is present in it, a
// |  |  single bit shall be added to the field-list in a bit-field of length one. The bit
// |  |  shall be set to 1 if the number of components in this encoding is not within the range
// |  |  of the extension root, and zero otherwise. In the former case 11.9 shall be invoked to
// |  |  add the length determinant as a semi-constrained whole number to the field-list,
// |  |  followed by the component values. In the latter case the length and value shall be
// |  |  encoded as if the extension marker is not present.
// |- 20.5 If the number of components is fixed ("ub" equals "lb") and "ub" is less than 64K,
// |  |  then there shall be no length determinant for the sequence-of, and the fields of each
// |  |  component shall be appended in turn to the field-list of the sequence-of.
// |- 20.6 Otherwise, the procedures of 11.9 shall be invoked to add the list of fields
// |  |  generated by the "n" components to the field-list, preceded by a length determinant
// |  |  equal to "n" components as a constrained whole number if "ub" is set, and as a
// |  |  semi-constrained whole number if "ub" is unset. "lb" is as determined above.
// |  |- NOTE 1 - The fragmentation procedures may apply after 16K, 32K, 48K, or 64K
// |  |  |  components.
// |  |- NOTE 2 - The break-points for fragmentation are between fields. The number of bits
// |  |  |  prior to a break-point are not necessarily a multiple of eight.

// 23 Encoding the choice type
// |- NOTE - (Tutorial) A choice type is encoded by encoding an index specifying the chosen
// |  |  alternative. This is encoded as for a constrained integer (unless the extension marker
// |  |  is present in the choice type, in which case it is a normally small non-negative whole
// |  |  number) and would therefore typically occupy a fixed length bit-field of the minimum
// |  |  number of bits needed to encode the index. (Although it could in principle be
// |  |  arbitrarily large.) This is followed by the encoding of the chosen alternative, with
// |  |  alternatives that are extension additions encoded as if they were the value of an open
// |  |  type field. Where the choice has only one alternative, there is no encoding for the
// |  |  index.
// |- 23.1 Encoding of choice types are not affected by PER-visible constraints.
// |- 23.2 Each component of a choice has an index associated with it which has the value zero
// |  |  for the first alternative in the root of the choice (taking the alternatives in the
// |  |  canonical order specified in Rec. ITU-T X.680 | ISO/IEC 8824-1, 8.6), one for the
// |  |  second, and so on up to the last component in the extension root of the choice. An
// |  |  index value is similarly assigned to each "NamedType" within the
// |  |  "ExtensionAdditionAlternativesList", starting with 0 just as with the components of
// |  |  the extension root. Let "n" be the value of the largest index in the root.
// |  |- NOTE - Rec. ITU-T X.680 | ISO/IEC 8824-1, 29.7, requires that each successive
// |  |  |  extension addition shall have a greater tag value than the last added to the
// |  |  |  "ExtensionAdditionAlternativesList".
// |- 23.3 For the purposes of canonical ordering of choice alternatives that contain an
// |  |  untagged choice, each untagged choice type shall be ordered as though it has a tag
// |  |  equal to that of the smallest tag in the extension root of either that choice type or
// |  |  any untagged choice types nested within.
// |- 23.4 If the choice has only one alternative in the extension root, there shall be no
// |  |  encoding for the index if that alternative is chosen.
// |- 23.5 If the choice type has an extension marker in the "AlternativeTypeLists"
// |  |  production, then a single bit shall first be added to the field-list in a bit-field of
// |  |  length one. The bit shall be 1 if a value of an extension addition is present in the
// |  |  encoding, and zero otherwise. (This bit is called the "extension bit" in the following
// |  |  text.) If there is no extension marker in the "AlternativeTypeLists" production, there
// |  |  shall be no extension bit added.
// |- 23.6 If the extension bit is absent, then the choice index of the chosen alternative
// |  |  shall be encoded into a field according to the procedures of clause 13 as if it were a
// |  |  value of an integer type (with no extension marker in its subtype constraint)
// |  |  constrained to the range 0 to "n", and that field shall be appended to the field-list.
// |  |  This shall then be followed by the fields of the chosen alternative, completing the
// |  |  procedures of this clause.
// |- 23.7 If the extension bit is present and the chosen alternative lies within the
// |  |  extension root, the choice index of the chosen alternative shall be encoded as if the
// |  |  extension marker is absent, according to the procedure of clause 13. This shall then
// |  |  be followed by the fields of the chosen alternative, completing the procedures of this
// |  |  clause.
// |- 23.8 If the extension bit is present and the chosen alternative does not lie within the
// |  |  extension root, the choice index of the chosen alternative shall be encoded as a
// |  |  normally small non-negative whole number with "lb" set to 0 and that field shall be
// |  |  appended to the field-list. This shall then be followed by a field-list containing the
// |  |  encoding of the chosen alternative encoded as if it were the value of an open type
// |  |  field as specified in 11.2, completing the procedures of this clause.
// |  |- NOTE - Version brackets in the definition of choice extension additions have no effect
// |  |  |  on how "ExtensionAdditionAlternatives" are encoded.
