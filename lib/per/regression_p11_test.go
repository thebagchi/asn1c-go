package per_test

import (
	"errors"
	"math"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestRegression_P11RealMantissaSign guards review P11-1.
// X.690 8.5.7.1 keeps the mantissa unsigned and puts the sign in bit 7.
// A mantissa of 2^63 with a clear sign bit is +2^63.
// _ParseBinaryReal casts the mantissa to int64 first, so that row decodes as -2^63.
// The row negative_one is a control, and it passes on the current code.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func TestRegression_P11RealMantissaSign(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want float64
	}{
		{
			name: "positive_power",
			data: []byte{
				0x0A,
				0x80,
				0x00,
				0x80,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
			},
			want: math.Ldexp(
				1,
				63,
			),
		},
		{
			name: "negative_one",
			data: []byte{
				0x03,
				0xC0,
				0x00,
				0x01,
			},
			want: -1,
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					_P11ExpectReal(
						t,
						DECODERS[aligned](tc.data),
						tc.want,
					)
				},
			)
		}
	}
}

// TestRegression_P11SemiConstrainedRange guards review P11-2.
// X.691 11.7 encodes the offset as a non-negative binary integer.
// An offset of 2^63 from 0 does not fit in int64, and the decoder must refuse it.
// DecodeSemiConstrainedWholeNumber casts the octets to int64 and returns MinInt64.
// The row offset_one is a control, and it passes on the current code.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func TestRegression_P11SemiConstrainedRange(t *testing.T) {
	refused := []struct {
		name string
		lb   int64
		data []byte
	}{
		{
			name: "offset_above_int64",
			lb:   0,
			data: []byte{
				0x08,
				0x80,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
			},
		},
		{
			name: "lower_bound_plus_one",
			lb:   math.MaxInt64,
			data: []byte{
				0x01,
				0x01,
			},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range refused {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					_P11RefuseSemi(
						t,
						DECODERS[aligned](tc.data),
						tc.lb,
					)
				},
			)
		}
	}

	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned]+"_offset_one",
			func(t *testing.T) {
				_P11AcceptSemi(
					t,
					DECODERS[aligned]([]byte{
						0x01,
						0x01,
					}),
					0,
					1,
				)
			},
		)
	}
}

// _P11ExpectReal checks that dec reads want.
// The sign bit is part of the value, so a negated power of two fails here.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func _P11ExpectReal(
	t *testing.T,
	dec *per.Decoder,
	want float64,
) {
	t.Helper()

	got, err := dec.DecodeReal()
	if err != nil {
		t.Fatalf(
			"DecodeReal() = %v",
			err,
		)
	}

	if got != want || math.Signbit(got) != math.Signbit(want) {
		t.Fatalf(
			"DecodeReal() = %g, want %g",
			got,
			want,
		)
	}
}

// _P11RefuseSemi checks that dec refuses lb plus the octets.
// The error wraps ErrValueOutOfRange, because the sum does not fit in int64.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func _P11RefuseSemi(
	t *testing.T,
	dec *per.Decoder,
	lb int64,
) {
	t.Helper()

	got, err := dec.DecodeSemiConstrainedWholeNumber(lb)
	if err == nil {
		t.Fatalf(
			"DecodeSemiConstrainedWholeNumber(%d) = %d, want ErrValueOutOfRange",
			lb,
			got,
		)
	}

	if !errors.Is(
		err,
		per.ErrValueOutOfRange,
	) {
		t.Fatalf(
			"error %v, want ErrValueOutOfRange",
			err,
		)
	}
}

// _P11AcceptSemi checks that dec reads want from a semi-constrained integer.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func _P11AcceptSemi(
	t *testing.T,
	dec *per.Decoder,
	lb int64,
	want int64,
) {
	t.Helper()

	got, err := dec.DecodeSemiConstrainedWholeNumber(lb)
	if err != nil {
		t.Fatalf(
			"DecodeSemiConstrainedWholeNumber(%d) = %v",
			lb,
			err,
		)
	}

	if got != want {
		t.Fatalf(
			"= %d, want %d",
			got,
			want,
		)
	}
}
