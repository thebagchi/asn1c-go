package per_test

import (
	"testing"
)

// TestBMPString_Vectors checks the encoding of every row of testing.json (strings) for BMPString
// against
// the octets of pycrate and OTP, then decodes those octets. BMPString is a known-multiplier
// type (X.691 clause 30.1), so X.691 clause 30.5 and a PER-visible SIZE (clause 10.3.9) apply.
// BMPString has 16 bits for every character, in both variants (X.691 clause 30.5.2 gives B =
// 16 and B2 = 16; the values of clause 30.5.3 are 0 to 2^16 - 1). The rows hold every
// character of the plane, a sample of each range of the plane, and every SIZE form. A Go
// string cannot hold a surrogate (U+D800 to U+DFFF), so no row has one.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestBMPString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"BMPString",
		_P5Visible,
	)
}

// TestBMPString_Framed writes every row of testing.json (strings) for BMPString between BOOLEAN
// fields
// and reads it back, in both variants (X.691 clause 30). The decoder must stop at the last bit
// of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestBMPString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"BMPString",
		_P5Visible,
	)
}

// TestGeneralString_Vectors checks the encoding of every row of testing.json (strings) for
// GeneralString
// against the octets of pycrate and OTP, then decodes those octets. GeneralString is not a
// known-multiplier type, so X.691 clause 30.6 applies: a SIZE is not PER-visible (clause
// 10.3.7), the type is never extensible for PER, and the value is an octet string behind an
// unconstrained length counted in octets (30.6.3, 11.9). The Go string carries the octets as
// they are, with no transcoding: the octets of the base encoding of X.690 clause 8.23.5 are
// the caller's. Pycrate writes ISO 2022 escape sequences for an octet above 0x7F, so rows with
// such an octet have OTP as the only oracle.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestGeneralString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"GeneralString",
		_P5Visible,
	)
}

// TestGeneralString_Framed writes every row of testing.json (strings) for GeneralString between
// BOOLEAN
// fields and reads it back, in both variants (X.691 clause 30). The decoder must stop at the
// last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestGeneralString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"GeneralString",
		_P5Visible,
	)
}

// TestGraphicString_Vectors checks the encoding of every row of testing.json (strings) for
// GraphicString
// against the octets of pycrate and OTP, then decodes those octets. GraphicString is not a
// known-multiplier type, so X.691 clause 30.6 applies: a SIZE is not PER-visible (clause
// 10.3.7), the type is never extensible for PER, and the value is an octet string behind an
// unconstrained length counted in octets (30.6.3, 11.9). The Go string carries the octets as
// they are, with no transcoding: the octets of the base encoding of X.690 clause 8.23.5 are
// the caller's. Pycrate writes ISO 2022 escape sequences for an octet above 0x7F, so rows with
// such an octet have OTP as the only oracle.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestGraphicString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"GraphicString",
		_P5Visible,
	)
}

// TestGraphicString_Framed writes every row of testing.json (strings) for GraphicString between
// BOOLEAN
// fields and reads it back, in both variants (X.691 clause 30). The decoder must stop at the
// last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestGraphicString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"GraphicString",
		_P5Visible,
	)
}

// TestIA5String_Vectors checks the encoding of every row of testing.json (strings) for IA5String
// against
// the octets of pycrate and OTP, then decodes those octets. IA5String is a known-multiplier
// type (X.691 clause 30.1), so X.691 clause 30.5 and a PER-visible SIZE (clause 10.3.9) apply.
// IA5String has 128 characters, so B = 7 and B2 = 8 (X.691 clause 30.5.2), and the characters
// keep their values (30.5.4 a). The rows hold every character 0 to 126, and U+007F in rows
// that only OTP answers (pycrate refuses U+007F in an IA5String).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestIA5String_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"IA5String",
		_P5Visible,
	)
}

// TestIA5String_Framed writes every row of testing.json (strings) for IA5String between BOOLEAN
// fields
// and reads it back, in both variants (X.691 clause 30). The decoder must stop at the last bit
// of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestIA5String_Framed(t *testing.T) {
	_P5Framed(
		t,
		"IA5String",
		_P5Visible,
	)
}

// TestISO646String_Vectors checks the encoding of every row of testing.json (strings) for
// ISO646String
// against the octets of pycrate and OTP, then decodes those octets. ISO646String is a
// known-multiplier type (X.691 clause 30.1), so X.691 clause 30.5 and a PER-visible SIZE
// (clause 10.3.9) apply. ISO646String is VisibleString (X.680 clause 41, Table 8), 95
// characters 32 to 126: B = 7 and B2 = 8, and the characters keep their values (X.691 clause
// 30.5.4 a). Pycrate reads the keyword; OTP does not, so OTP answers the rows through
// VisibleString.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestISO646String_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"ISO646String",
		_P5Visible,
	)
}

// TestISO646String_Framed writes every row of testing.json (strings) for ISO646String between
// BOOLEAN
// fields and reads it back, in both variants (X.691 clause 30). The decoder must stop at the
// last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestISO646String_Framed(t *testing.T) {
	_P5Framed(
		t,
		"ISO646String",
		_P5Visible,
	)
}

// TestNumericString_Vectors checks the encoding of every row of testing.json (strings) for
// NumericString
// against the octets of pycrate and OTP, then decodes those octets. NumericString is a
// known-multiplier type (X.691 clause 30.1), so X.691 clause 30.5 and a PER-visible SIZE
// (clause 10.3.9) apply. NumericString has 11 characters, space and 0 to 9, so B = B2 = 4
// (X.691 clause 30.5.2). The largest value is 57, which does not fit in 4 bits, so the
// characters are numbered from 0 in canonical order (30.5.4 b): space is 0 and 9 is 10.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestNumericString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"NumericString",
		_P5Visible,
	)
}

// TestNumericString_Framed writes every row of testing.json (strings) for NumericString between
// BOOLEAN
// fields and reads it back, in both variants (X.691 clause 30). The decoder must stop at the
// last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestNumericString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"NumericString",
		_P5Visible,
	)
}

// TestPrintableString_Vectors checks the encoding of every row of testing.json (strings) for
// PrintableString against the octets of pycrate and OTP, then decodes those octets.
// PrintableString is a known-multiplier type (X.691 clause 30.1), so X.691 clause 30.5 and a
// PER-visible SIZE (clause 10.3.9) apply. PrintableString has 74 characters, so B = 7 and B2 =
// 8 (X.691 clause 30.5.2). The largest value is 122, which fits in 7 and in 8 bits, so the
// characters keep their values (30.5.4 a).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestPrintableString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"PrintableString",
		_P5Visible,
	)
}

// TestPrintableString_Framed writes every row of testing.json (strings) for PrintableString
// between
// BOOLEAN fields and reads it back, in both variants (X.691 clause 30). The decoder must stop
// at the last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestPrintableString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"PrintableString",
		_P5Visible,
	)
}

// TestTeletexString_Vectors checks the encoding of every row of testing.json (strings) for
// TeletexString
// against the octets of pycrate and OTP, then decodes those octets. TeletexString is not a
// known-multiplier type, so X.691 clause 30.6 applies: a SIZE is not PER-visible (clause
// 10.3.7), the type is never extensible for PER, and the value is an octet string behind an
// unconstrained length counted in octets (30.6.3, 11.9). The Go string carries the octets as
// they are, with no transcoding: the octets of the base encoding of X.690 clause 8.23.5 are
// the caller's. Pycrate writes ISO 2022 escape sequences for an octet above 0x7F, so rows with
// such an octet have OTP as the only oracle.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestTeletexString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"TeletexString",
		_P5Visible,
	)
}

// TestTeletexString_Framed writes every row of testing.json (strings) for TeletexString between
// BOOLEAN
// fields and reads it back, in both variants (X.691 clause 30). The decoder must stop at the
// last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestTeletexString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"TeletexString",
		_P5Visible,
	)
}

// TestT61String_Vectors checks the encoding of every row of testing.json (strings) for T61String
// against
// the octets of pycrate and OTP, then decodes those octets. T61String is not a
// known-multiplier type, so X.691 clause 30.6 applies: a SIZE is not PER-visible (clause
// 10.3.7), the type is never extensible for PER, and the value is an octet string behind an
// unconstrained length counted in octets (30.6.3, 11.9). The Go string carries the octets as
// they are, with no transcoding: the octets of the base encoding of X.690 clause 8.23.5 are
// the caller's. Pycrate writes ISO 2022 escape sequences for an octet above 0x7F, so rows with
// such an octet have OTP as the only oracle.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestT61String_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"T61String",
		_P5Visible,
	)
}

// TestT61String_Framed writes every row of testing.json (strings) for T61String between BOOLEAN
// fields
// and reads it back, in both variants (X.691 clause 30). The decoder must stop at the last bit
// of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestT61String_Framed(t *testing.T) {
	_P5Framed(
		t,
		"T61String",
		_P5Visible,
	)
}

// TestUniversalString_Vectors checks the encoding of every row of testing.json (strings) for
// UniversalString against the octets of pycrate and OTP, then decodes those octets.
// UniversalString is a known-multiplier type (X.691 clause 30.1), so X.691 clause 30.5 and a
// PER-visible SIZE (clause 10.3.9) apply. UniversalString has 32 bits for every character in
// both variants (X.691 clause 30.5.3: the values are 0 to 2^32 - 1). The rows hold a sample
// over every plane up to U+10FFFF, which is as far as a Go string goes, and a stride over the
// whole range.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestUniversalString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"UniversalString",
		_P5Visible,
	)
}

// TestUniversalString_Framed writes every row of testing.json (strings) for UniversalString
// between
// BOOLEAN fields and reads it back, in both variants (X.691 clause 30). The decoder must stop
// at the last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestUniversalString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"UniversalString",
		_P5Visible,
	)
}

// TestUTF8String_Vectors checks the encoding of every row of testing.json (strings) for UTF8String
// against the octets of pycrate and OTP, then decodes those octets. UTF8String is not a
// known-multiplier type, so X.691 clause 30.6 applies: a SIZE or FROM is not PER-visible
// (clause 10.3.7) and the type is never extensible for PER, so the value is the octets of its
// UTF-8 form behind an unconstrained length counted in octets (30.6.3, 11.9). The length is in
// octets, not in characters, and a fragment of 16K octets can end in the middle of a
// character.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestUTF8String_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"UTF8String",
		_P5Visible,
	)
}

// TestUTF8String_Framed writes every row of testing.json (strings) for UTF8String between BOOLEAN
// fields
// and reads it back, in both variants (X.691 clause 30). The decoder must stop at the last bit
// of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestUTF8String_Framed(t *testing.T) {
	_P5Framed(
		t,
		"UTF8String",
		_P5Visible,
	)
}

// TestVideotexString_Vectors checks the encoding of every row of testing.json (strings) for
// VideotexString against the octets of pycrate and OTP, then decodes those octets.
// VideotexString is not a known-multiplier type, so X.691 clause 30.6 applies: a SIZE is not
// PER-visible (clause 10.3.7), the type is never extensible for PER, and the value is an octet
// string behind an unconstrained length counted in octets (30.6.3, 11.9). The Go string
// carries the octets as they are, with no transcoding: the octets of the base encoding of
// X.690 clause 8.23.5 are the caller's. Pycrate writes ISO 2022 escape sequences for an octet
// above 0x7F, so rows with such an octet have OTP as the only oracle.
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestVideotexString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"VideotexString",
		_P5Visible,
	)
}

// TestVideotexString_Framed writes every row of testing.json (strings) for VideotexString between
// BOOLEAN fields and reads it back, in both variants (X.691 clause 30). The decoder must stop
// at the last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestVideotexString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"VideotexString",
		_P5Visible,
	)
}

// TestVisibleString_Vectors checks the encoding of every row of testing.json (strings) for
// VisibleString
// against the octets of pycrate and OTP, then decodes those octets. VisibleString is a
// known-multiplier type (X.691 clause 30.1), so X.691 clause 30.5 and a PER-visible SIZE
// (clause 10.3.9) apply. VisibleString has 95 characters 32 to 126, so B = 7 and B2 = 8, and
// the characters keep their values (X.691 clause 30.5.4 a).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestVisibleString_Vectors(t *testing.T) {
	_P5Vectors(
		t,
		"VisibleString",
		_P5Visible,
	)
}

// TestVisibleString_Framed writes every row of testing.json (strings) for VisibleString between
// BOOLEAN
// fields and reads it back, in both variants (X.691 clause 30). The decoder must stop at the
// last bit of the value, also after a fragmented length (11.9.3.8).
//
// Revisions:
//   - 2026-10-19 12:45: initial creation
func TestVisibleString_Framed(t *testing.T) {
	_P5Framed(
		t,
		"VisibleString",
		_P5Visible,
	)
}
