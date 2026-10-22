package per_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// KIND_OCTET lists the types of X.691 clause 30.6, which carry the value as an octet
// string, with the Go string the tests use for them.
var (
	KIND_OCTET = []string{
		"GeneralString",
		"GraphicString",
		"TeletexString",
		"T61String",
		"UTF8String",
		"VideotexString",
	}

	// KIND_EXTENSIBLE_FROM lists the types that have rows with an extensible FROM.
	KIND_EXTENSIBLE_FROM = []string{
		"BMPString",
		"IA5String",
		"NumericString",
		"PrintableString",
		"UniversalString",
		"VisibleString",
	}
)

// TestStringKind_Constants checks the new kinds and the two aliases (X.680 clause 41,
// Table 8). T61String is TeletexString and ISO646String is VisibleString, so a kind
// has one value for each spelling. Every kind must index the alphabet tables, which
// have STRING_KINDS entries.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestStringKind_Constants(t *testing.T) {
	if per.STRING_T61 != per.STRING_TELETEX {
		t.Errorf(
			"STRING_T61 = %d, want STRING_TELETEX = %d",
			per.STRING_T61,
			per.STRING_TELETEX,
		)
	}

	if per.STRING_ISO646 != per.STRING_VISIBLE {
		t.Errorf(
			"STRING_ISO646 = %d, want STRING_VISIBLE = %d",
			per.STRING_ISO646,
			per.STRING_VISIBLE,
		)
	}

	seen := make(map[per.StringKind]string)

	for name, kind := range STRING_KIND_VALUES {
		if kind < 0 || kind >= per.STRING_KINDS {
			t.Errorf(
				"%s = %d, outside the %d kinds",
				name,
				kind,
				per.STRING_KINDS,
			)
		}

		if other, ok := seen[kind]; ok && !_P5Alias(
			name,
			other,
		) {
			t.Errorf(
				"%s and %s are both kind %d",
				name,
				other,
				kind,
			)
		}

		seen[kind] = name
	}
}

// _P5Alias reports whether two type names are spellings of one type.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func _P5Alias(
	left,
	right string,
) bool {
	pair := map[string]string{
		"ISO646String":  "VisibleString",
		"VisibleString": "ISO646String",
		"T61String":     "TeletexString",
		"TeletexString": "T61String",
	}

	return pair[left] == right
}

// TestFromExtensible_Vectors checks the types whose FROM is extensible. X.691 clause
// 10.3.11 makes a permitted-alphabet constraint PER-visible only if it is not
// extensible, and 10.3.20 NOTE 2 gives IA5String (SIZE(1..4)) (FROM("ABCD", ...)) as
// an example: the alphabet is the whole IA5String alphabet, the SIZE stays. So a caller
// encodes the type with the parent kind and the SIZE. The rows come from pycrate
// only: OTP stops with an internal error on an extensible FROM
// (asn1ct_imm:string_num_bits).
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestFromExtensible_Vectors(t *testing.T) {
	for _, kind := range KIND_EXTENSIBLE_FROM {
		t.Run(
			kind,
			func(t *testing.T) {
				_P5Vectors(
					t,
					kind,
					_P5Hidden,
				)
			},
		)
	}
}

// TestFromExtensible_Framed is TestFromExtensible_Vectors with BOOLEAN fields before
// and after the value.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestFromExtensible_Framed(t *testing.T) {
	for _, kind := range KIND_EXTENSIBLE_FROM {
		t.Run(
			kind,
			func(t *testing.T) {
				_P5Framed(
					t,
					kind,
					_P5Hidden,
				)
			},
		)
	}
}

// TestRestrictedString_SizeNotVisible checks that a SIZE changes nothing for the types
// of X.691 clause 30.6. Clause 10.3.7 says a constraint on a type that is not a
// known-multiplier type is not PER-visible, and 30.6.3 asks for an unconstrained length
// determinant. So every SIZE form, fixed, range, semi-constrained and extensible, gives
// the octets of the unconstrained type, with no extension bit (30.6: the type can never
// be extensible for PER), and the decoder reads the unconstrained form.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestRestrictedString_SizeNotVisible(t *testing.T) {
	var (
		sizes = map[string]*per.Constraint{
			"fixed": per.Constrained(
				3,
				3,
			),
			"range": per.Constrained(
				1,
				4,
			),
			"semi":    per.SemiConstrained(2),
			"bounded": per.Bounded(10),
			"extensible_one": per.Constrained(
				3,
				3,
			).Extensible(),
			"extensible_two": per.Constrained(
				1,
				4,
			).Extensible(),
			"large": per.Constrained(
				0,
				100000,
			),
			"large_ext": per.Constrained(
				1,
				70000,
			).Extensible(),
		}

		values = map[string]string{
			"in_root":  "abc",
			"short":    "a",
			"outside":  "abcdefgh",
			"empty":    "",
			"high_utf": "\u00e9\u4e2d",
		}
	)

	for _, name := range KIND_OCTET {
		kind := STRING_KIND_VALUES[name]

		for sizeName, size := range sizes {
			for valueName, value := range values {
				for _, aligned := range []bool{true, false} {
					t.Run(
						strings.Join(
							[]string{
								name,
								sizeName,
								valueName,
								VARIANT_NAMES[aligned],
							},
							"/",
						),
						func(t *testing.T) {
							_P5CheckSizeNotVisible(
								t,
								aligned,
								&_P5SizeCase{
									kind:  kind,
									size:  size,
									value: value,
								},
							)
						},
					)
				}
			}
		}
	}
}

// _P5SizeCase is one kind, SIZE and value of TestRestrictedString_SizeNotVisible.
type _P5SizeCase struct {
	kind  per.StringKind
	size  *per.Constraint
	value string
}

// _P5CheckSizeNotVisible encodes a value with and without a SIZE and compares the two,
// then decodes the unconstrained octets with the SIZE.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func _P5CheckSizeNotVisible(
	t *testing.T,
	aligned bool,
	tc *_P5SizeCase,
) {
	t.Helper()

	var (
		kind, size, value = tc.kind, tc.size, tc.value

		plain = ENCODERS[aligned]()
	)
	if err := plain.EncodeRestrictedString(
		value,
		kind,
		per.Unconstrained(),
	); err != nil {
		t.Fatalf(
			"encode without SIZE = %v",
			err,
		)
	}

	sized := ENCODERS[aligned]()
	if err := sized.EncodeRestrictedString(
		value,
		kind,
		size,
	); err != nil {
		t.Fatalf(
			"encode with SIZE = %v",
			err,
		)
	}

	_Compare(
		t,
		sized.Bytes(),
		plain.Bytes(),
	)

	got, err := DECODERS[aligned](plain.Bytes()).DecodeRestrictedString(
		kind,
		size,
	)
	if err != nil {
		t.Fatalf(
			"decode with SIZE = %v",
			err,
		)
	}

	if got != value {
		t.Fatalf(
			"decode with SIZE = %q, want %q",
			got,
			value,
		)
	}
}

// TestUTF8String_InvalidUTF8 checks that a UTF8String must hold well-formed UTF-8.
// X.680 clause 41 defines the type as the characters of ISO/IEC 10646 in the UTF-8
// form, and X.691 clause 30.6.2 takes the base encoding of that value. A byte sequence
// that is not well-formed UTF-8 is no character string, on encode and on decode: an
// overlong form, a surrogate, a stray continuation octet, a cut sequence. Each case
// has a valid control row.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestUTF8String_InvalidUTF8(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
		valid bool
	}{
		{
			name:  "control_ascii",
			bytes: []byte("abc"),
			valid: true,
		},
		{
			name:  "control_four_octets",
			bytes: []byte("\U0001F600"),
			valid: true,
		},
		{
			name:  "lone_continuation",
			bytes: []byte{'a', 0x80},
		},
		{
			name:  "invalid_lead",
			bytes: []byte{0xFF, 0xFE},
		},
		{
			name:  "truncated_three",
			bytes: []byte{'a', 0xE6, 0x97},
		},
		{
			name:  "overlong_slash",
			bytes: []byte{0xC0, 0xAF},
		},
		{
			name:  "surrogate",
			bytes: []byte{0xED, 0xA0, 0x80},
		},
		{
			name:  "above_10ffff",
			bytes: []byte{0xF4, 0x90, 0x80, 0x80},
		},
	}

	for _, tc := range cases {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					var (
						enc = ENCODERS[aligned]()

						encErr = enc.EncodeRestrictedString(
							string(tc.bytes),
							per.STRING_UTF8,
							per.Unconstrained(),
						)

						data = append(
							[]byte{byte(len(tc.bytes))},
							tc.bytes...,
						)
						dec       = DECODERS[aligned](data)
						_, decErr = dec.DecodeRestrictedString(
							per.STRING_UTF8,
							per.Unconstrained(),
						)
					)

					if tc.valid {
						_P5ExpectAccepted(
							t,
							encErr,
							decErr,
						)

						return
					}

					_P5ExpectRefused(
						t,
						encErr,
						decErr,
					)
				},
			)
		}
	}
}

// _P5ExpectAccepted checks that a valid case passes on both sides.
//
// Revisions:
//   - 2026-10-19 12:50: initial creation
func _P5ExpectAccepted(
	t *testing.T,
	encErr,
	decErr error,
) {
	t.Helper()

	if encErr != nil || decErr != nil {
		t.Fatalf(
			"encode = %v, decode = %v, want no error",
			encErr,
			decErr,
		)
	}
}

// _P5ExpectRefused checks that an invalid case is refused on both sides.
//
// Revisions:
//   - 2026-10-19 12:50: initial creation
func _P5ExpectRefused(
	t *testing.T,
	encErr,
	decErr error,
) {
	t.Helper()

	if encErr == nil {
		t.Errorf("encode = nil, want an error")
	}

	if decErr == nil {
		t.Errorf("decode = nil, want an error")
	}
}

// _P5Given reports whether an answer of an oracle is present: it is not null.
//
// Revisions:
//   - 2026-10-20 00:36: initial creation
func _P5Given(answer json.RawMessage) bool {
	return len(answer) > 0 && string(answer) != "null"
}

// _P5Answered reports whether a row has an oracle answer for each variant.
//
// Revisions:
//   - 2026-10-19 12:50: initial creation
//   - 2026-10-20 00:36: read the answers of both oracles (py and er), not the list of oracles
func _P5Answered(row *_P5Row) bool {
	if row.Oracles == nil {
		return false
	}

	return row.Oracles.Aper != nil && row.Oracles.Uper != nil &&
		(_P5Given(row.Oracles.Aper.Py) || _P5Given(row.Oracles.Aper.Er)) &&
		(_P5Given(row.Oracles.Uper.Py) || _P5Given(row.Oracles.Uper.Er))
}

// TestRestrictedString_InvalidUTF8 checks the Go string that is not UTF-8. A Go string
// holds bytes, and a range over it turns a bad byte into U+FFFD. U+FFFD is a character
// of BMPString and UniversalString, so a codec that took it would turn a bad byte into
// another value without a word. The tests ask for a refusal on encode. The types with
// a narrower alphabet refuse U+FFFD already (X.691 clause 30.5.3); the control row of
// each kind is the same text in valid form.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestRestrictedString_InvalidUTF8(t *testing.T) {
	kinds := []string{
		"BMPString",
		"IA5String",
		"NumericString",
		"PrintableString",
		"UniversalString",
		"VisibleString",
	}

	for _, name := range kinds {
		for _, aligned := range []bool{true, false} {
			t.Run(
				name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					var (
						kind = STRING_KIND_VALUES[name]

						enc = ENCODERS[aligned]()

						control = enc.EncodeRestrictedString(
							"1",
							kind,
							per.Unconstrained(),
						)
					)
					if control != nil {
						t.Fatalf(
							"control = %v",
							control,
						)
					}

					err := ENCODERS[aligned]().EncodeRestrictedString(
						"1\xff2",
						kind,
						per.Unconstrained(),
					)
					if err == nil {
						t.Errorf("encode of a bad byte = nil")
					}
				},
			)
		}
	}
}

// TestRestrictedString_DecodeOutOfAlphabet hands the decoder a value that no character
// of the type has. Each case is an input, not an encoding: the first octet is the
// length (11.9.3.6), the rest the one bad character. The control row of each case is
// the nearest good character. The values are those of X.691 clause 30.5.3 (VisibleString
// 32 to 126; PrintableString 7 bits with no value 33; NumericString 4 bits with the
// values 11 to 15 unused).
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestRestrictedString_DecodeOutOfAlphabet(t *testing.T) {
	cases := []struct {
		name    string
		kind    per.StringKind
		aligned bool
		data    []byte
		valid   bool
	}{
		{
			name:    "visible_aper_control_a",
			kind:    per.STRING_VISIBLE,
			aligned: true,
			data:    []byte{0x01, 0x61},
			valid:   true,
		},
		{
			name:    "visible_aper_below_32",
			kind:    per.STRING_VISIBLE,
			aligned: true,
			data:    []byte{0x01, 0x01},
		},
		{
			name:  "visible_uper_control_a",
			kind:  per.STRING_VISIBLE,
			data:  []byte{0x01, 0xC2},
			valid: true,
		},
		{
			name: "visible_uper_below_32",
			kind: per.STRING_VISIBLE,
			data: []byte{0x01, 0x02},
		},
		{
			name:    "printable_aper_control_space",
			kind:    per.STRING_PRINTABLE,
			aligned: true,
			data:    []byte{0x01, 0x20},
			valid:   true,
		},
		{
			name:    "printable_aper_bang",
			kind:    per.STRING_PRINTABLE,
			aligned: true,
			data:    []byte{0x01, 0x21},
		},
		{
			name: "printable_uper_bang",
			kind: per.STRING_PRINTABLE,
			data: []byte{0x01, 0x42},
		},
		{
			name:    "numeric_aper_control_nine",
			kind:    per.STRING_NUMERIC,
			aligned: true,
			data:    []byte{0x01, 0xA0},
			valid:   true,
		},
		{
			name:    "numeric_aper_eleven",
			kind:    per.STRING_NUMERIC,
			aligned: true,
			data:    []byte{0x01, 0xB0},
		},
		{
			name: "numeric_uper_fifteen",
			kind: per.STRING_NUMERIC,
			data: []byte{0x01, 0xF0},
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				var (
					dec    = DECODERS[tc.aligned](tc.data)
					_, err = dec.DecodeRestrictedString(
						tc.kind,
						per.Unconstrained(),
					)
				)

				if tc.valid && err != nil {
					t.Fatalf(
						"decode = %v, want no error",
						err,
					)
				}

				if !tc.valid && err == nil {
					t.Fatalf("decode = nil, want an error")
				}

				if !tc.valid && !errors.Is(
					err,
					per.ErrCharacterNotInAlphabet,
				) {
					t.Fatalf(
						"decode = %v, want ErrCharacterNotInAlphabet",
						err,
					)
				}
			},
		)
	}
}

// TestRestrictedString_DecodeNotAScalar hands the decoder a BMPString or
// UniversalString character that is not a Unicode scalar value: a surrogate, or a
// value above U+10FFFF. X.691 clause 30.5.3 gives the type 2^16 or 2^32 values, but the
// characters of ISO/IEC 10646 are the scalar values, and a Go string cannot hold the
// rest, so the decoder refuses them. The input is the length octet 1 and the character
// (11.9.3.6); in both variants the field is a whole number of octets here.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestRestrictedString_DecodeNotAScalar(t *testing.T) {
	cases := []struct {
		name  string
		kind  per.StringKind
		data  []byte
		valid bool
	}{
		{
			name:  "bmp_control_ffff",
			kind:  per.STRING_BMP,
			data:  []byte{0x01, 0xFF, 0xFD},
			valid: true,
		},
		{
			name: "bmp_d800",
			kind: per.STRING_BMP,
			data: []byte{0x01, 0xD8, 0x00},
		},
		{
			name: "bmp_dfff",
			kind: per.STRING_BMP,
			data: []byte{0x01, 0xDF, 0xFF},
		},
		{
			name:  "universal_control_10ffff",
			kind:  per.STRING_UNIVERSAL,
			data:  []byte{0x01, 0x00, 0x10, 0xFF, 0xFF},
			valid: true,
		},
		{
			name: "universal_d800",
			kind: per.STRING_UNIVERSAL,
			data: []byte{0x01, 0x00, 0x00, 0xD8, 0x00},
		},
		{
			name: "universal_110000",
			kind: per.STRING_UNIVERSAL,
			data: []byte{0x01, 0x00, 0x11, 0x00, 0x00},
		},
		{
			name: "universal_7fffffff",
			kind: per.STRING_UNIVERSAL,
			data: []byte{0x01, 0x7F, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "universal_ffffffff",
			kind: per.STRING_UNIVERSAL,
			data: []byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tc := range cases {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					var (
						dec    = DECODERS[aligned](tc.data)
						_, err = dec.DecodeRestrictedString(
							tc.kind,
							per.Unconstrained(),
						)
					)

					if tc.valid && err != nil {
						t.Fatalf(
							"decode = %v, want no error",
							err,
						)
					}

					if !tc.valid && err == nil {
						t.Fatalf("decode = nil, want an error")
					}
				},
			)
		}
	}
}

// TestRestrictedString_DecodeTruncated cuts the last octet off one encoding of each
// type, in both variants: the length says more characters than the input holds, so the
// decoder must return an error and not a short string. The encoding is the one the
// vector row "nosize/n8" gives (the encoder is checked against the oracles in the
// Vectors tests).
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestRestrictedString_DecodeTruncated(t *testing.T) {
	for name, kind := range STRING_KIND_VALUES {
		for _, aligned := range []bool{true, false} {
			t.Run(
				name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					var (
						row = _P5Find(
							t,
							name,
							name+"/nosize/n8",
						)
						value = _P5Value(
							t,
							row,
						)

						enc = ENCODERS[aligned]()
					)
					if err := enc.EncodeRestrictedString(
						value,
						kind,
						per.Unconstrained(),
					); err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					var (
						whole = enc.Bytes()
						dec   = DECODERS[aligned](whole[:len(whole)-1])

						_, err = dec.DecodeRestrictedString(
							kind,
							per.Unconstrained(),
						)
					)
					if err == nil {
						t.Errorf(
							"decode of %d of %d octets = nil",
							len(whole)-1,
							len(whole),
						)
					}
				},
			)
		}
	}
}

// _P5Find returns the row of a type with a given identifier.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func _P5Find(
	t *testing.T,
	kind,
	id string,
) *_P5Row {
	t.Helper()

	for _, row := range _P5Rows(
		t,
		kind,
	) {
		if row.ID == id {
			return row
		}
	}

	t.Fatalf(
		"no row %s",
		id,
	)

	return nil
}

// TestRestrictedString_OraclesAnswered checks the vector file itself: every row has at
// least one oracle for each variant, and a row that the oracles answered differently
// names the oracle that X.691 supports. Without this, a generator that dropped an
// oracle would make the vector tests weaker without a word.
//
// Revisions:
//   - 2026-10-19 12:46: initial creation
func TestRestrictedString_OraclesAnswered(t *testing.T) {
	for name := range STRING_KIND_VALUES {
		for _, row := range _P5Rows(
			t,
			name,
		) {
			if !_P5Answered(row) {
				t.Errorf(
					"%s: no oracle in %+v",
					row.ID,
					row.Oracles,
				)
			}
		}
	}
}
