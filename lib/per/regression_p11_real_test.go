package per_test

import (
	"math"
	"testing"
)

// TestRegression_P11RealWideExponent guards review P11-1.
// X.690 8.5.7 gives the value as M x B^E, with M = S x N x 2^F.
// The test computes the want with math.Ldexp on the summed binary exponent:
// F plus E times log2(B). That sum never forms B^E alone.
// _ParseBinaryReal computes B^E alone, which underflows to 0 when M x B^E is subnormal.
// The factor B^E alone is below 2^-1074 in each wide row, though M x B^E is a subnormal.
// The rows wide_base2, wide_base16 and wide_base8_scale fail on that code.
// The row control_small passes today. The rows max_power are the upper edge.
// The octets are first octet, two exponent octets, then the mantissa octets.
//
// Revisions:
//   - 2026-10-20 01:14: initial creation
func TestRegression_P11RealWideExponent(t *testing.T) {
	cases := []struct {
		name     string
		first    byte
		exponent []byte
		mantissa []byte
		want     float64
	}{
		{
			name:     "wide_base2",
			first:    0x81,
			exponent: []byte{0xFB, 0xB4},
			mantissa: []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: math.Ldexp(
				1,
				52-1100,
			),
		},
		{
			name:     "wide_base16",
			first:    0xA1,
			exponent: []byte{0xFE, 0xF2},
			mantissa: []byte{0x10, 0x00},
			want: math.Ldexp(
				1,
				12+4*-270,
			),
		},
		{
			name:     "wide_base8_scale",
			first:    0x9D,
			exponent: []byte{0xFE, 0x96},
			mantissa: []byte{0x10, 0x00, 0x00},
			want: math.Ldexp(
				1,
				20+3+3*-362,
			),
		},
		{
			name:     "control_small",
			first:    0x81,
			exponent: []byte{0x00, 0x04},
			mantissa: []byte{0x03},
			want:     48,
		},
		{
			name:     "max_power_one",
			first:    0x81,
			exponent: []byte{0x03, 0xFF},
			mantissa: []byte{0x01},
			want: math.Ldexp(
				1,
				1023,
			),
		},
		{
			name:     "max_power_wide_mantissa",
			first:    0x81,
			exponent: []byte{0x03, 0xF5},
			mantissa: []byte{0x04, 0x00},
			want: math.Ldexp(
				1,
				10+1013,
			),
		},
		{
			name:     "max_power_one_negative",
			first:    0xC1,
			exponent: []byte{0x03, 0xFF},
			mantissa: []byte{0x01},
			want: -math.Ldexp(
				1,
				1023,
			),
		},
		{
			name:     "max_power_wide_mantissa_negative",
			first:    0xC1,
			exponent: []byte{0x03, 0xF5},
			mantissa: []byte{0x04, 0x00},
			want: -math.Ldexp(
				1,
				10+1013,
			),
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					contents := []byte{tc.first}
					contents = append(
						contents,
						tc.exponent...,
					)
					contents = append(
						contents,
						tc.mantissa...,
					)

					data := []byte{byte(len(contents))}
					data = append(
						data,
						contents...,
					)

					_P11ExpectReal(
						t,
						DECODERS[aligned](data),
						tc.want,
					)
				},
			)
		}
	}
}
