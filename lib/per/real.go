package per

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// Sentinel errors for the REAL contents octets of X.690 clause 8.5.
var (
	ErrRealTruncated  = errors.New("real contents octets end early")
	ErrRealReserved   = errors.New("real uses a reserved encoding")
	ErrRealMantissa   = errors.New("real mantissa is wider than 64 bits")
	ErrRealNotANumber = errors.New("real is not a number")
)

// Real is a real number in the form X.690 clause 8.5 encodes: a mantissa scaled
// by a base raised to an exponent.
//
// It exists because MakeReal has three things to say about a float64 and two of
// them are ints, which a bare multiple return would leave a caller to tell apart
// by position.
type Real struct {
	mantissa int64
	exponent int
	base     int
}

// NewReal returns the real number mantissa * base**exponent.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func NewReal(mantissa int64, exponent, base int) *Real {
	return &Real{
		mantissa: mantissa,
		exponent: exponent,
		base:     base,
	}
}

// MakeReal decomposes a float64 into the mantissa, exponent and base X.690
// clause 8.5.7 encodes.
//
// The mantissa is made odd, as clause 11.3.1 requires for CER and DER and
// therefore for PER: the same value can be written with many mantissa and
// exponent pairs, and dividing out the factors of two picks the one every
// encoder agrees on.
//
// Revisions:
//   - 2026-02-04 22:23: initial creation
//   - 2026-09-22 06:43: returns a Real rather than three bare numbers, two of
//     which were ints a caller had to tell apart by position
func MakeReal(value float64) *Real {
	if value == 0.0 || math.IsInf(value, 0) || math.IsNaN(value) {
		return NewReal(0, 0, REAL_BASE_TWO)
	}

	var (
		raw  = math.Float64bits(value)
		sign = (raw >> DOUBLE_SIGN_BIT_POS) & 1
		exp  = int((raw >> DOUBLE_MANTISSA_BITS) & DOUBLE_EXPONENT_MASK)
		frac = raw & DOUBLE_MANTISSA_MASK
	)

	var (
		mantissa int64
		exponent int
	)

	if exp == 0 {
		mantissa = int64(frac)
		exponent = DOUBLE_SUBNORMAL_EXP - DOUBLE_MANTISSA_BITS
	} else {
		mantissa = int64(uint64(1)<<DOUBLE_MANTISSA_BITS | frac)
		exponent = exp - DOUBLE_EXPONENT_BIAS - DOUBLE_MANTISSA_BITS
	}

	// Dividing out the trailing zero bits is what makes the mantissa odd, and
	// the shift count is exactly how far the exponent moves to compensate.
	if mantissa != 0 {
		shift := bits.TrailingZeros64(uint64(mantissa))
		mantissa >>= shift
		exponent += shift
	}

	if sign == 1 {
		mantissa = -mantissa
	}

	return NewReal(mantissa, exponent, REAL_BASE_TWO)
}

// Mantissa returns the signed mantissa.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (r *Real) Mantissa() int64 {
	return r.mantissa
}

// Exponent returns the exponent the base is raised to.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (r *Real) Exponent() int {
	return r.exponent
}

// Base returns the base, which clause 8.5.7.2 restricts to 2, 8 or 16 for a
// binary encoding and 8.5.8 fixes at 10 for a decimal one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (r *Real) Base() int {
	return r.base
}

// Float returns the value as a float64.
//
// A base that is a power of two is applied with Ldexp, which scales through the
// exponent field exactly; math.Pow would route the same value through a
// logarithm and return something a round trip no longer reproduces.
//
// Revisions:
//   - 2026-02-19 18:19: initial creation
//   - 2026-09-22 06:43: became a method on Real
func (r *Real) Float() float64 {
	switch r.base {
	case REAL_BASE_TWO:
		return math.Ldexp(float64(r.mantissa), r.exponent)
	case REAL_BASE_EIGHT:
		return math.Ldexp(float64(r.mantissa), r.exponent*REAL_BASE_EIGHT_LOG)
	case REAL_BASE_SIXTEEN:
		return math.Ldexp(float64(r.mantissa), r.exponent*REAL_BASE_SIXTEEN_LOG)
	case REAL_BASE_TEN:
		return math.Pow10(r.exponent) * float64(r.mantissa)
	default:
		return math.Pow(float64(r.base), float64(r.exponent)) * float64(r.mantissa)
	}
}

// _RealContents renders value as the contents octets of X.690 clause 8.5.
//
// Plus zero is empty, per clause 8.5.2, and the special values are the single
// octets of clause 8.5.9; everything else takes the binary form of clause 8.5.7
// with base 2 and a scaling factor of zero, which is what clause 11.3.1 pins
// down for a canonical encoding.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Encoder.EncodeReal, whose
//     fifteen unchecked writes into a second bit buffer this replaces with a
//     byte slice that cannot fail
func _RealContents(value float64) []byte {
	switch {
	case math.IsNaN(value):
		return []byte{REAL_NOT_A_NUMBER}
	case math.IsInf(value, 1):
		return []byte{REAL_PLUS_INFINITY}
	case math.IsInf(value, -1):
		return []byte{REAL_MINUS_INFINITY}
	case value == 0.0 && math.Signbit(value):
		return []byte{REAL_MINUS_ZERO}
	case value == 0.0:
		return nil
	}

	parts := MakeReal(value)

	mantissa := parts.Mantissa()

	first := byte(REAL_BINARY_FLAG)
	if mantissa < 0 {
		first = first | REAL_BINARY_SIGN_BIT
		mantissa = -mantissa
	}

	exponent := _ExponentOctets(parts.Exponent())

	// Clause 8.5.7.5 numbers the one, two and three octet forms 0, 1 and 2, and
	// reserves 3 for a leading length octet.
	if len(exponent) > EXPONENT_24_OCTETS {
		first = first | REAL_EXPONENT_LONG
	} else {
		first = first | byte(len(exponent)-1)
	}

	contents := []byte{first}
	if len(exponent) > EXPONENT_24_OCTETS {
		contents = append(contents, byte(len(exponent)))
	}

	contents = append(contents, exponent...)

	return append(contents, _MantissaOctets(uint64(mantissa))...)
}

// _ParseReal reads the contents octets of X.690 clause 8.5.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Decoder.DecodeReal, which
//     returned zero and no error at five points where the octets ran out, and
//     read a decimal encoding as though it were binary
func _ParseReal(contents []byte) (float64, error) {
	if len(contents) == 0 {
		return 0.0, nil
	}

	first := contents[0]

	// Clause 8.5.6 a): bit 8 selects the binary form.
	if first&REAL_BINARY_FLAG != 0 {
		return _ParseBinaryReal(contents)
	}

	// Clause 8.5.6 c): bit 8 clear and bit 7 set is a special value.
	if first&REAL_SPECIAL_FLAG != 0 {
		return _ParseSpecialReal(first)
	}

	// Clause 8.5.6 b): both clear is the decimal form of clause 8.5.8.
	return _ParseDecimalReal(contents)
}

// _ParseSpecialReal reads the single contents octet of X.690 clause 8.5.9.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ParseSpecialReal(first byte) (float64, error) {
	switch first {
	case REAL_PLUS_INFINITY:
		return math.Inf(1), nil
	case REAL_MINUS_INFINITY:
		return math.Inf(-1), nil
	case REAL_NOT_A_NUMBER:
		return math.NaN(), nil
	case REAL_MINUS_ZERO:
		return math.Copysign(0, -1), nil
	default:
		return 0, fmt.Errorf("first octet %#02x: %w", first, ErrRealReserved)
	}
}

// _ParseDecimalReal reads the ISO 6093 form of X.690 clause 8.5.8.
//
// ISO 6093 permits a comma as the decimal mark, which Go's parser does not, so
// the one is rewritten to the other before parsing rather than reimplementing
// the grammar around it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ParseDecimalReal(contents []byte) (float64, error) {
	if first := contents[0] & LENGTH_SIX_BIT_MASK; first > REAL_NR3_FORM {
		return 0, fmt.Errorf("number representation %d: %w", first, ErrRealReserved)
	}

	text := strings.TrimSpace(string(contents[1:]))
	text = strings.ReplaceAll(text, ",", ".")

	if text == "" {
		return 0, fmt.Errorf("decimal form: %w", ErrRealTruncated)
	}

	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("decimal form %q: %w", text, err)
	}

	return value, nil
}

// _ParseBinaryReal reads the binary form of X.690 clause 8.5.7.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ParseBinaryReal(contents []byte) (float64, error) {
	first := contents[0]

	exponent, rest, err := _ReadExponent(contents)
	if err != nil {
		return 0, err
	}

	if len(rest) > MAX_VALUE_OCTETS {
		return 0, fmt.Errorf("%d octets: %w", len(rest), ErrRealMantissa)
	}

	mantissa := _BigEndian(rest)

	// Clause 8.5.7.3: the scaling factor multiplies the mantissa by 2**F. PER
	// only ever writes zero, but a decoder reads what it is given.
	scale := int((first >> REAL_SCALE_SHIFT) & REAL_SCALE_MASK)

	signed := int64(mantissa)
	if first&REAL_BINARY_SIGN_BIT != 0 {
		signed = -signed
	}

	base, err := _ReadBase(first)
	if err != nil {
		return 0, err
	}

	return NewReal(signed<<scale, exponent, base).Float(), nil
}

// _ReadBase reads the base from bits 6 and 5 of the first contents octet, per
// X.690 clause 8.5.7.2.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ReadBase(first byte) (int, error) {
	switch (first >> REAL_BASE_SHIFT) & REAL_BASE_MASK {
	case REAL_BASE_SELECT_2:
		return REAL_BASE_TWO, nil
	case REAL_BASE_SELECT_8:
		return REAL_BASE_EIGHT, nil
	case REAL_BASE_SELECT_16:
		return REAL_BASE_SIXTEEN, nil
	default:
		return 0, fmt.Errorf("base selector 3: %w", ErrRealReserved)
	}
}

// _ReadExponent reads the exponent of X.690 clause 8.5.7.5 and returns it with
// the mantissa octets that follow it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ReadExponent(contents []byte) (int, []byte, error) {
	var (
		form  = contents[0] & REAL_EXPONENT_MASK
		start = 1
		width int
	)

	switch form {
	case REAL_EXPONENT_ONE, REAL_EXPONENT_TWO, REAL_EXPONENT_THREE:
		width = int(form) + 1
	default:
		if len(contents) < DER_HEADER_OCTETS {
			return 0, nil, fmt.Errorf("exponent length octet: %w", ErrRealTruncated)
		}

		width = int(contents[1])
		start = DER_HEADER_OCTETS

		if width == 0 {
			return 0, nil, fmt.Errorf("exponent of zero octets: %w", ErrRealReserved)
		}
	}

	end := start + width
	if end > len(contents) {
		return 0, nil, fmt.Errorf("%d exponent octets: %w", width, ErrRealTruncated)
	}

	if width > MAX_VALUE_OCTETS {
		return 0, nil, fmt.Errorf("%d exponent octets: %w", width, ErrRealMantissa)
	}

	return int(_SignExtend(_BigEndian(contents[start:end]), width)), contents[end:], nil
}

// _BigEndian reads up to MAX_VALUE_OCTETS octets as one big-endian number.
//
// Shifting the octets in one at a time rather than right-aligning them in an
// array and taking one load: measured, the array form is 2% faster on a REAL
// decode and costs 349 bytes of generated code across this function, its two
// callers and _Octets. A REAL is decoded once per value, so the code is worth
// more than the two percent.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation, replacing two copies of this loop
func _BigEndian(octets []byte) uint64 {
	var value uint64
	for _, octet := range octets {
		value = value<<BITS_PER_BYTE | uint64(octet)
	}

	return value
}

// _Octets renders value as its width lowest-order octets, most significant
// first. It is _BigEndian's inverse, and the note there applies to it too.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation, replacing two copies of this loop
func _Octets(value uint64, width int) []byte {
	if width <= 0 {
		return nil
	}

	octets := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		octets[i] = byte(value)
		value >>= BITS_PER_BYTE
	}

	return octets
}

// _SignExtend reads raw as a two's complement number of width octets.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _SignExtend(raw uint64, width int) int64 {
	shift := uint(UINT64_BITS - width*BITS_PER_BYTE)

	return int64(raw<<shift) >> shift
}

// _ExponentOctets renders exponent as the fewest two's complement octets that
// hold it, per X.690 clause 8.5.7.5.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ExponentOctets(exponent int) []byte {
	return _Octets(uint64(exponent), OctetsTwosComplementBinaryInteger(int64(exponent)))
}

// _MantissaOctets renders an unsigned mantissa as the fewest octets that hold
// it, which is none when it is zero.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _MantissaOctets(mantissa uint64) []byte {
	if mantissa == 0 {
		return nil
	}

	return _Octets(mantissa, OctetsNonNegativeBinaryIntegerLength(mantissa))
}
