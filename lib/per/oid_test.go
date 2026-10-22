package per_test

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// P4_SKIP_WIDE is why a framed test skips a row whose arc is above the platform int.
const (
	P4_SKIP_WIDE = "an arc is above the platform int; the vector tests check the refusal"
)

type _P4Arcs struct {
	_P4Oracles
	Type  string  `json:"type"`
	Value []int64 `json:"value"`
}

type _P4OIDFile struct {
	OID []*_P4Arcs `json:"oid"`
}

type _P4RelativeOIDFile struct {
	RelativeOID []*_P4Arcs `json:"relative_oid"`
}

// TestObjectIdentifier_Vectors checks EncodeObjectIdentifier against the octets
// of pycrate and OTP (testing/oid.py), and DecodeObjectIdentifier against the same
// octets. X.691 clause 24 puts the contents octets of BER (X.690 clause 8.19)
// behind a length determinant. The first two arcs share one subidentifier
// (8.19.4), and an arc is written base 128 with the shortest form (8.19.2). The
// arcs reach 2^31, 2^32, 2^53 and math.MaxInt64, which encoding/asn1 does not
// decode.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-21 21:51: a row whose arc is above the platform int (a 32-bit platform) checks
//     the refusal of the decoder (review P31)
func TestObjectIdentifier_Vectors(t *testing.T) {
	var file _P4OIDFile

	_Load(
		t,
		VECTOR_OID,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.OID {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_ArcsName(tc.Value),
				func(t *testing.T) {
					var (
						want = _Unhex(
							t,
							_Both(
								tc.Aper,
								tc.Uper,
							)[aligned],
						)

						arcs, fits = _PlatformArcs(tc.Value)
					)
					if !fits {
						var (
							dec    = DECODERS[aligned](want)
							_, err = dec.DecodeObjectIdentifier()
						)

						_CheckArcRefused(
							t,
							err,
						)

						return
					}

					var (
						in  = asn1.ObjectIdentifier(arcs)
						enc = ENCODERS[aligned]()
					)
					if err := enc.EncodeObjectIdentifier(in); err != nil {
						t.Fatalf(
							"EncodeObjectIdentifier() = %v",
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						want,
					)

					var (
						dec = DECODERS[aligned](want)

						got, err = dec.DecodeObjectIdentifier()
					)
					if err != nil {
						t.Fatalf(
							"DecodeObjectIdentifier() = %v",
							err,
						)
					}

					if !got.Equal(in) {
						t.Fatalf(
							"decode = %v, want %v",
							got,
							tc.Value,
						)
					}
				},
			)
		}
	}
}

// TestRegression_ObjectIdentifierRoundTrip guards lib/review.md finding 2.5: an
// OBJECT IDENTIFIER has a decoder, and that decoder stops at the last bit of the
// value. It replaces the test of that name which P1 removed with the
// reflection code. Each vector value goes between BOOLEAN fields (X.691
// clause 24, 11.9).
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-21 21:51: a row whose arc is above the platform int (a 32-bit platform) checks
//     the refusal of the decoder (review P31)
func TestRegression_ObjectIdentifierRoundTrip(t *testing.T) {
	var file _P4OIDFile

	_Load(
		t,
		VECTOR_OID,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.OID {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_ArcsName(tc.Value),
				func(t *testing.T) {
					arcs, fits := _PlatformArcs(tc.Value)
					if !fits {
						t.Skip(P4_SKIP_WIDE)
					}

					in := asn1.ObjectIdentifier(arcs)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeObjectIdentifier(in)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeObjectIdentifier()
							if err == nil && !got.Equal(in) {
								t.Errorf(
									"decode = %v, want %v",
									got,
									in,
								)
							}

							return err
						},
					)
				},
			)
		}
	}
}

// TestObjectIdentifier_EncodeRefused checks values that have no encoding. X.680
// clause 32.3 and X.660 give an object identifier at least two arcs; the first
// arc is 0, 1 or 2, and the second is below 40 when the first is 0 or 1 (X.690
// clause 8.19.4 packs them as 40*first+second). An arc is a non-negative number.
// The control case is a valid value.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
func TestObjectIdentifier_EncodeRefused(t *testing.T) {
	cases := []struct {
		name  string
		value asn1.ObjectIdentifier
		valid bool
	}{
		{
			name:  "control_valid",
			value: asn1.ObjectIdentifier{1, 2, 840},
			valid: true,
		},
		{
			name:  "nil",
			value: nil,
		},
		{
			name:  "empty",
			value: asn1.ObjectIdentifier{},
		},
		{
			name:  "one_arc_0",
			value: asn1.ObjectIdentifier{0},
		},
		{
			name:  "one_arc_1",
			value: asn1.ObjectIdentifier{1},
		},
		{
			name:  "one_arc_2",
			value: asn1.ObjectIdentifier{2},
		},
		{
			name:  "first_arc_3",
			value: asn1.ObjectIdentifier{3, 0},
		},
		{
			name:  "first_arc_large",
			value: asn1.ObjectIdentifier{math.MaxInt, 0},
		},
		{
			name:  "second_arc_40_under_0",
			value: asn1.ObjectIdentifier{0, 40},
		},
		{
			name:  "second_arc_40_under_1",
			value: asn1.ObjectIdentifier{1, 40},
		},
		{
			name:  "second_arc_large_under_1",
			value: asn1.ObjectIdentifier{1, 999},
		},
		{
			name:  "negative_first",
			value: asn1.ObjectIdentifier{-1, 2},
		},
		{
			name:  "negative_second",
			value: asn1.ObjectIdentifier{1, -1},
		},
		{
			name:  "negative_third",
			value: asn1.ObjectIdentifier{1, 2, -3},
		},
		{
			name:  "negative_second_under_2",
			value: asn1.ObjectIdentifier{2, -1},
		},
		{
			name:  "min_int64_late",
			value: asn1.ObjectIdentifier{1, 2, math.MinInt},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					err := ENCODERS[aligned]().EncodeObjectIdentifier(tc.value)

					if tc.valid {
						if err != nil {
							t.Fatalf(
								"EncodeObjectIdentifier() = %v",
								err,
							)
						}

						return
					}

					if err == nil {
						t.Fatalf("error = nil, want an error")
					}
				},
			)
		}
	}
}

// TestObjectIdentifier_DecodeRefused checks contents octets that are not a
// valid encoding. Each input is the length octet and the contents. A
// subidentifier has no leading octet 0x80, which is padding (X.690 clause
// 8.19.2), and its last octet has bit 8 clear. Contents with no subidentifier
// are not an object identifier (clause 8.19.1 asks for at least one). An arc
// above math.MaxInt64 does not fit the Go int. The control cases are valid.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-19 11:45: control_2_999 has length 2, as its contents hold two octets
func TestObjectIdentifier_DecodeRefused(t *testing.T) {
	cases := []struct {
		name  string
		data  []byte
		want  asn1.ObjectIdentifier
		valid bool
	}{
		{
			name:  "control_1_2",
			data:  []byte{0x01, 0x2A},
			want:  asn1.ObjectIdentifier{1, 2},
			valid: true,
		},
		{
			name:  "control_2_999",
			data:  []byte{0x02, 0x88, 0x37},
			want:  asn1.ObjectIdentifier{2, 999},
			valid: true,
		},
		{
			name: "no_contents",
			data: []byte{0x00},
		},
		{
			name: "first_subidentifier_padded",
			data: []byte{0x02, 0x80, 0x2A},
		},
		{
			name: "later_arc_padded",
			data: []byte{0x04, 0x2A, 0x80, 0x80, 0x01},
		},
		{
			name: "later_arc_padded_one_octet",
			data: []byte{0x03, 0x2A, 0x80, 0x01},
		},
		{
			name: "last_arc_truncated",
			data: []byte{0x02, 0x2A, 0x86},
		},
		{
			name: "first_subidentifier_truncated",
			data: []byte{0x01, 0x86},
		},
		{
			name: "arc_above_int64",
			data: []byte{
				0x0B, 0x2A, 0x81, 0x80, 0x80, 0x80, 0x80,
				0x80, 0x80, 0x80, 0x80, 0x00,
			},
		},
		{
			name: "length_above_input",
			data: []byte{0x05, 0x2A},
		},
		{
			name: "empty_input",
			data: []byte{},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					var (
						dec      = DECODERS[aligned](tc.data)
						got, err = dec.DecodeObjectIdentifier()
					)

					if tc.valid {
						if err != nil {
							t.Fatalf(
								"DecodeObjectIdentifier() = %v",
								err,
							)
						}

						if !got.Equal(tc.want) {
							t.Fatalf(
								"decode = %v, want %v",
								got,
								tc.want,
							)
						}

						return
					}

					if err == nil {
						t.Fatalf(
							"decode = %v, want an error",
							got,
						)
					}
				},
			)
		}
	}
}

// _ArcsName builds the subtest name of an arc list. A long list shows its
// length.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-21 21:51: takes the int64 arcs of a vector row (review P31)
func _ArcsName(arcs []int64) string {
	if len(arcs) > 8 {
		return fmt.Sprintf(
			"%d_arcs_from_%v",
			len(arcs),
			arcs[:4],
		)
	}

	return fmt.Sprintf(
		"%v",
		arcs,
	)
}

// _PlatformArcs converts the arcs of a vector row to Go ints, the type of the API. An arc
// above the platform int (2^31 and more on a 32-bit platform) does not fit, and the second
// result is false.
//
// Revisions:
//   - 2026-10-21 21:51: initial creation (review P31)
func _PlatformArcs(values []int64) ([]int, bool) {
	arcs := make(
		[]int,
		len(values),
	)

	for idx, value := range values {
		if int64(int(value)) != value {
			return nil, false
		}

		arcs[idx] = int(value)
	}

	return arcs, true
}

// _CheckArcRefused checks that a decoder refused an arc above the platform int with
// ErrValueOutOfRange: the value has no Go int form there, so the edge refuses it.
//
// Revisions:
//   - 2026-10-21 21:51: initial creation (review P31)
func _CheckArcRefused(
	t *testing.T,
	err error,
) {
	t.Helper()

	if !errors.Is(
		err,
		per.ErrValueOutOfRange,
	) {
		t.Fatalf(
			"decode = %v, want ErrValueOutOfRange for an arc above the platform int",
			err,
		)
	}
}
