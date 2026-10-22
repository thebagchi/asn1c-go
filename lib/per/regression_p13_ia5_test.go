package per_test

import (
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// P13_KINDS are the 8-bit known-multiplier kinds of review P13-5.
var (
	P13_KINDS = []per.StringKind{
		per.STRING_IA5,
		per.STRING_VISIBLE,
		per.STRING_PRINTABLE,
	}
)

// _P13Shape is one value of TestRegression_P13OctetCharacters: the BOOLEAN bits in front, the
// SIZE, the value, and the octets it encodes to in each variant.
type _P13Shape struct {
	name   string
	prefix int
	size   *per.Constraint
	value  string
	aper   string
	uper   string
}

// TestRegression_P13OctetCharacters guards review P13-5: the octet of an 8-bit character is
// the character only in the ALIGNED variant. UPER IA5String, VisibleString and
// PrintableString keep their 7-bit field, so "A" must not become the single octet 41.
// pycrate 0.8.1 and OTP 29.1.1 both give APER 0141 and UPER 0182 for "A" in all three types.
//
// A fixed size after a BOOLEAN is not aligned when aub * b is not above 16 (X.691 30.5.6), so
// WriteBytes writes at a bit offset there. SIZE (1) "A" is APER a080, UPER c1, from both
// oracles. SIZE (2) "AB" is 16 bits: pycrate gives APER a0a100 and OTP gives 804142, an
// aligned field; 30.5.6 aligns only above 16, so a0a100 stands (review P21-4). Both give
// UPER c184. Every row also decodes back.
//
// Revisions:
//   - 2026-10-20 01:37: initial creation
//   - 2026-10-21 02:44: rows SIZE (1) and SIZE (2) after a BOOLEAN, and a decode of every row
//     (review P21-4)
func TestRegression_P13OctetCharacters(t *testing.T) {
	shapes := []*_P13Shape{
		{
			name:  "plain",
			size:  per.Unconstrained(),
			value: "A",
			aper:  "0141",
			uper:  "0182",
		},
		{
			name:   "size1_after_boolean",
			prefix: 1,
			size: per.Constrained(
				1,
				1,
			),
			value: "A",
			aper:  "a080",
			uper:  "c1",
		},
		{
			name:   "size2_after_boolean",
			prefix: 1,
			size: per.Constrained(
				2,
				2,
			),
			value: "AB",
			aper:  "a0a100",
			uper:  "c184",
		},
	}

	for _, kind := range P13_KINDS {
		for _, shape := range shapes {
			for _, aligned := range []bool{true, false} {
				name := strconv.Itoa(int(kind)) + "_" + shape.name
				t.Run(
					name+"_"+VARIANT_NAMES[aligned],
					func(t *testing.T) {
						_P13CheckShape(
							t,
							aligned,
							kind,
							shape,
						)
					},
				)
			}
		}
	}
}

// TestRegression_P13BadByte guards review P13-5: a byte outside the alphabet is refused on
// the octet path too. Each value is ASCII, so it takes the byte path, and one of its
// bytes is outside the alphabet of the type.
//
// Revisions:
//   - 2026-10-20 01:37: initial creation
func TestRegression_P13BadByte(t *testing.T) {
	cases := []struct {
		name  string
		kind  per.StringKind
		value string
	}{
		{
			name:  "visible_control",
			kind:  per.STRING_VISIBLE,
			value: "AB\x01CDEFGH",
		},
		{
			name:  "visible_delete",
			kind:  per.STRING_VISIBLE,
			value: "ABCDEFG\x7f",
		},
		{
			name:  "printable_at",
			kind:  per.STRING_PRINTABLE,
			value: "A@BCDEFGH",
		},
	}

	for _, tc := range cases {
		for _, aligned := range []bool{true, false} {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					enc := per.NewUnalignedEncoder()
					if aligned {
						enc = per.NewAlignedEncoder()
					}

					err := enc.EncodeRestrictedString(
						tc.value,
						tc.kind,
						per.Unconstrained(),
					)
					if !errors.Is(
						err,
						per.ErrCharacterNotInAlphabet,
					) {
						t.Fatalf(
							"error = %v, want %v",
							err,
							per.ErrCharacterNotInAlphabet,
						)
					}
				},
			)
		}
	}
}

// _P13CheckShape encodes one shape, compares the octets, and decodes the value back.
//
// Revisions:
//   - 2026-10-20 01:37: initial creation, as _P13ExpectOctets
//   - 2026-10-21 02:44: writes the BOOLEAN bits and the SIZE of the shape, and decodes back
func _P13CheckShape(
	t *testing.T,
	aligned bool,
	kind per.StringKind,
	shape *_P13Shape,
) {
	t.Helper()

	enc := ENCODERS[aligned]()
	for range shape.prefix {
		if err := enc.EncodeBoolean(true); err != nil {
			t.Fatal(err)
		}
	}

	err := enc.EncodeRestrictedString(
		shape.value,
		kind,
		shape.size,
	)
	if err != nil {
		t.Fatal(err)
	}

	var (
		want = map[bool]string{
			true:  shape.aper,
			false: shape.uper,
		}[aligned]

		got = enc.Bytes()
	)
	if hex.EncodeToString(got) != want {
		t.Fatalf(
			"encoded %x, want %s",
			got,
			want,
		)
	}

	dec := DECODERS[aligned](got)
	for range shape.prefix {
		if _, err := dec.DecodeBoolean(); err != nil {
			t.Fatal(err)
		}
	}

	back, err := dec.DecodeRestrictedString(
		kind,
		shape.size,
	)
	if err != nil || back != shape.value {
		t.Fatalf(
			"decoded %q, %v; want %q",
			back,
			err,
			shape.value,
		)
	}
}
