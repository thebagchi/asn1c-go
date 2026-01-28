package per

import (
	"math/bits"

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
	return bits.Len64(uint64(-value))
}

func OctetsTwosComplementBinaryIntegerLength(value int64) int {
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
		bits := BitsNonNegativeBinaryInteger(uint64(vr))
		value := uint64(n - lb)
		return e.codec.Write(uint8(bits), value)
	}

	value := uint64(n - lb)
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
	if vr == 0x100 {
		if err := e.codec.Align(); nil != err {
			return err
		}
		return e.codec.Write(8, value)
	}
	if vr >= 0x101 && vr <= 0x10000 {
		if err := e.codec.Align(); nil != err {
			return err
		}
		return e.codec.Write(16, value)
	}
	return e.EncodeUnconstrainedWholeNumber(int64(value))
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
		if err := e.codec.Write(0, 1); err != nil {
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
	if err := e.codec.Align(); nil != err {
		return err
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
	octets := OctetsTwosComplementBinaryIntegerLength(n)
	if octets == 0 {
		octets = 1
	}
	if err := e.codec.Align(); nil != err {
		return err
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
	const K64 = 65536 // 64K
	if ub != nil && lb != nil && (*ub-*lb+1) < K64 {
		err := e.EncodeConstrainedWholeNumber(int64(*lb), int64(*ub), int64(n))
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	return e.EncodeUnconstrainedLength(n)
}

func (e *Encoder) EncodeUnconstrainedLength(n uint64) (uint64, error) {
	const K = 16384 // 16K = 16 * 1024

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

	if n < K {
		value := (1 << 15) | n
		if err := e.codec.Write(16, value); err != nil {
			return 0, err
		}
		return 0, nil
	}

	m := CalculateFragmentSize(n)
	k := m / K

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
	const K = 16384 // 16K = 16 * 1024

	if n >= 4*K {
		return 4 * K // 64K
	} else if n >= 3*K {
		return 3 * K // 48K
	} else if n >= 2*K {
		return 2 * K // 32K
	} else {
		return K // 16K
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
		bound := uint64(*ub - *lb + 1)
		if bound > 65536 {
			return e.EncodeSemiConstrainedWholeNumber(*lb, value)
		}
		return e.EncodeConstrainedWholeNumber(*lb, *ub, value)
	} else if lb != nil && ub == nil {
		return e.EncodeSemiConstrainedWholeNumber(*lb, value)
	} else {
		return e.EncodeUnconstrainedWholeNumber(value)
	}
}

// 14 Encoding the enumerated type
// |- NOTE - (Tutorial) An enumerated type without an extension marker is encoded as if it were a constrained integer whose subtype
// |  |  constraint does not contain an extension marker. This means that an enumerated type will almost always in practice be encoded as
// |  |  a bit-field in the smallest number of bits needed to express every enumeration. In the presence of an extension marker, it is encoded
// |  |  as a normally small non-negative whole number if the value is not in the extension root.
// |- 14.1 The enumerations in the enumeration root shall be sorted into ascending order by their enumeration value, and
// |  |  shall then be assigned an enumeration index starting with zero for the first enumeration, one for the second, and so on up
// |  |  to the last enumeration in the sorted list. The extension additions (which are always defined in ascending order) shall be
// |  |  assigned an enumeration index starting with zero for the first enumeration, one for the second, and so on up to the last
// |  |  enumeration in the extension additions.
// |  |- NOTE - Rec. ITU-T X.680 | ISO/IEC 8824-1 requires that each successive extension addition shall have a greater enumeration
// |  |  |  value than the last.
// |- 14.2 If the extension marker is absent in the definition of the enumerated type, then the enumeration index shall be
// |  |  encoded. Its encoding shall be as though it were a value of a constrained integer type for which there is no extension
// |  |  marker present, where the lower bound is 0 and the upper bound is the largest enumeration index associated with the type,
// |  |  completing this procedure.
// |- 14.3 If the extension marker is present, then a single bit shall be added to the field-list in a bit-field of length one.
// |  |  The bit shall be set to 1 if the value to be encoded is not within the extension root, and zero otherwise. In the former case,
// |  |  the enumeration additions shall be sorted according to 14.1 and the value shall be added to the field-list as a normally
// |  |  small non-negative whole number whose value is the enumeration index of the additional enumeration and with "lb" set
// |  |  to 0, completing this procedure. In the latter case, the value shall be encoded as if the extension marker is not present, as
// |  |  specified in 14.2.
// |  |- NOTE - There are no PER-visible constraints that can be applied to an enumerated type that are visible to these encoding rules.

// 15 Encoding the real type
// |- NOTE - (Tutorial) A real uses the contents octets of CER/DER preceded by a length determinant that will in practice be a single
// |  |  octet.
// |- 15.1 If the base of the abstract value is 10, then the base of the encoded value shall be 10, and if the base of the
// |  |  abstract value is 2 the base of the encoded value shall be 2.
// |- 15.2 The encoding of REAL specified for CER and DER in Rec. ITU-T X.690 | ISO/IEC 8825-1, 11.3 shall be applied
// |  |  to give a bit-field (octet-aligned in the ALIGNED variant) which is the contents octets of the CER/DER encoding. The
// |  |  contents octets of this encoding consists of "n" (say) octets and is placed in a bit-field (octet-aligned in the ALIGNED
// |  |  variant) of "n" octets. The procedures of 11.9 shall be invoked to append this bit-field (octet-aligned in the ALIGNED
// |  |  variant) of "n" octets to the field-list, preceded by an unconstrained length determinant equal to "n".

// 16 Encoding the bitstring type
// |- NOTE - (Tutorial) Bitstrings constrained to a fixed length less than or equal to 16 bits do not cause octet alignment. Larger
// |  |  bitstrings are octet-aligned in the ALIGNED variant. If the length is fixed by constraints and the upper bound is less than 64K,
// |  |  there is no explicit length encoding, otherwise a length encoding is included which can take any of the forms specified earlier for
// |  |  length encodings, including fragmentation for large bit strings.
// |- 16.1 PER-visible constraints can only constrain the length of the bitstring.
// |- 16.2 Where there are no PER-visible constraints and Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.7, applies the value
// |  |  shall be encoded with no trailing 0 bits (note that this means that a value with no 1 bits is always encoded as an empty bit
// |  |  string).
// |- 16.3 Where there is a PER-visible constraint and Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.7, applies (i.e., the bitstring
// |  |  type is defined with a "NamedBitList"), the value shall be encoded with trailing 0 bits added or removed as necessary to
// |  |  ensure that the size of the transmitted value is the smallest size capable of carrying this value and satisfies the effective
// |  |  size constraint.
// |- 16.4 Let the maximum number of bits in the bitstring (as determined by PER-visible constraints on the length) be
// |  |  "ub" and the minimum number of bits be "lb". If there is no finite maximum we say that "ub" is unset. If there is no
// |  |  constraint on the minimum, then "lb" has the value zero. Let the length of the actual bit string value to be encoded be
// |  |  "n" bits.
// |- 16.5 When a bitstring value is placed in a bit-field as specified in 16.6 to 16.11, the leading bit of the bitstring value
// |  |  shall be placed in the leading bit of the bit-field, and the trailing bit of the bitstring value shall be placed in the trailing bit
// |  |  of the bit-field.
// |- 16.6 If the type is extensible for PER encodings (see 10.3.9), then a bit-field consisting of a single bit shall be added
// |  |  to the field-list. The bit shall be set to 1 if the length of this encoding is not within the range of the extension root, and
// |  |  zero otherwise. In the former case, 16.11 shall be invoked to add the length as a semi-constrained whole number to the
// |  |  field-list, followed by the bitstring value. In the latter case the length and value shall be encoded as if no extension is
// |  |  present in the constraint.
// |- 16.7 If an extension marker is not present in the constraint specification of the bitstring type, then 16.8 to 16.11
// |  |  apply.
// |- 16.8 If the bitstring is constrained to be of zero length ("ub" equals zero), then it shall not be encoded (no additions
// |  |  to the field-list), completing the procedures of this clause.
// |- 16.9 If all values of the bitstring are constrained to be of the same length ("ub" equals "lb") and that length is less
// |  |  than or equal to sixteen bits, then the bitstring shall be placed in a bit-field of the constrained length "ub" which shall be
// |  |  appended to the field-list with no length determinant, completing the procedures of this clause.
// |- 16.10 If all values of the bitstring are constrained to be of the same length ("ub" equals "lb") and that length is greater
// |  |  than sixteen bits but less than 64K bits, then the bitstring shall be placed in a bit-field (octet-aligned in the ALIGNED
// |  |  variant) of length "ub" (which is not necessarily a multiple of eight bits) and shall be appended to the field-list with no
// |  |  length determinant, completing the procedures of this clause.
// |- 16.11 If 16.8-16.10 do not apply, the bitstring shall be placed in a bit-field (octet-aligned in the ALIGNED variant)
// |  |  of length "n" bits and the procedures of 11.9 shall be invoked to add this bit-field (octet-aligned in the ALIGNED variant)
// |  |  of "n" bits to the field-list, preceded by a length determinant equal to "n" bits as a constrained whole number if "ub" is set
// |  |  and is less than 64K or as a semi-constrained whole number if "ub" is unset. "lb" is as determined above.
// |  |- NOTE - Fragmentation applies for unconstrained or large "ub" after 16K, 32K, 48K or 64K bits.

// 17 Encoding the octetstring type
// |- NOTE - Octet strings of fixed length less than or equal to two octets are not octet-aligned. All other octet strings are octet-aligned
// |  |  in the ALIGNED variant. Fixed length octet strings encode with no length octets if they are shorter than 64K. For unconstrained
// |  |  octet strings the length is explicitly encoded (with fragmentation if necessary).
// |- 17.1 PER-visible constraints can only constrain the length of the octetstring.
// |- 17.2 Let the maximum number of octets in the octetstring (as determined by PER-visible constraints on the length)
// |  |  be "ub" and the minimum number of octets be "lb". If there is no finite maximum, we say that "ub" is unset. If there is no
// |  |  constraint on the minimum, then "lb" has the value zero. Let the length of the actual octetstring value to be encoded be
// |  |  "n" octets.
// |- 17.3 If the type is extensible for PER encodings (see 10.3.9), then a bit-field consisting of a single bit shall be added
// |  |  to the field-list. The bit shall be set to 1 if the length of this encoding is not within the range of the extension root, and
// |  |  zero otherwise. In the former case 17.8 shall be invoked to add the length as a semi-constrained whole number to the
// |  |  field-list, followed by the octetstring value. In the latter case the length and value shall be encoded as if no extension is
// |  |  present in the constraint.
// |- 17.4 If an extension marker is not present in the constraint specification of the octetstring type, then 17.5 to 17.8
// |  |  apply.
// |- 17.5 If the octetstring is constrained to be of zero length ("ub" equals zero), then it shall not be encoded (no additions
// |  |  to the field-list), completing the procedures of this clause.
// |- 17.6 If all values of the octetstring are constrained to be of the same length ("ub" equals "lb") and that length is less
// |  |  than or equal to two octets, the octetstring shall be placed in a bit-field with a number of bits equal to the constrained
// |  |  length "ub" multiplied by eight which shall be appended to the field-list with no length determinant, completing the
// |  |  procedures of this clause.
// |- 17.7 If all values of the octetstring are constrained to be of the same length ("ub" equals "lb") and that length is
// |  |  greater than two octets but less than 64K, then the octetstring shall be placed in a bit-field (octet-aligned in the ALIGNED
// |  |  variant) with the constrained length "ub" octets which shall be appended to the field-list with no length determinant,
// |  |  completing the procedures of this clause.
// |- 17.8 If 17.5 to 17.7 do not apply, the octetstring shall be placed in a bit-field (octet-aligned in the ALIGNED variant)
// |  |  of length "n" octets and the procedures of 11.9 shall be invoked to add this bit-field (octet-aligned in the ALIGNED
// |  |  variant) of "n" octets to the field-list, preceded by a length determinant equal to "n" octets as a constrained whole number
// |  |  if "ub" is set, and as a semi-constrained whole number if "ub" is unset. "lb" is as determined above.
// |  |- NOTE - The fragmentation procedures may apply after 16K, 32K, 48K, or 64K octets.

// 18 Encoding the null type
// |- NOTE - (Tutorial) The null type is essentially a place holder, with practical meaning only in the case of a choice or an optional set
// |  |  or sequence component. Identification of the null in a choice, or its presence as an optional element, is performed in these encoding
// |  |  rules without the need to have octets representing the null. Null values therefore never contribute to the octets of an encoding.
// |  |  There shall be no addition to the field-list for a null value.
