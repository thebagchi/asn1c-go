package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestBitsNonNegativeBinaryInteger checks the bit width of X.691 clause 11.3.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestBitsNonNegativeBinaryInteger(t *testing.T) {
	cases := []struct {
		name  string
		value uint64
		want  int
	}{
		{
			name:  "zero_still_needs_a_bit",
			value: 0,
			want:  1,
		},
		{
			name:  "one",
			value: 1,
			want:  1,
		},
		{
			name:  "two",
			value: 2,
			want:  2,
		},
		{
			name:  "max_uint64",
			value: ^uint64(0),
			want:  64,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got := per.BitsNonNegativeBinaryInteger(tc.value)

				if got != tc.want {
					t.Errorf(
						"= %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}
}

// TestOctetsNonNegativeBinaryIntegerLength checks the octet width of clause 11.3.6.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestOctetsNonNegativeBinaryIntegerLength(t *testing.T) {
	cases := []struct {
		name  string
		value uint64
		want  int
	}{
		{
			name:  "zero",
			value: 0,
			want:  1,
		},
		{
			name:  "max_one_octet",
			value: 0xFF,
			want:  1,
		},
		{
			name:  "needs_two",
			value: 0x100,
			want:  2,
		},
		{
			name:  "max_two_octets",
			value: 0xFFFF,
			want:  2,
		},
		{
			name:  "needs_three",
			value: 0x10000,
			want:  3,
		},
		{
			name:  "max_uint32",
			value: 0xFFFFFFFF,
			want:  4,
		},
		{
			name:  "needs_five",
			value: 0x100000000,
			want:  5,
		},
		{
			name:  "max_uint64",
			value: ^uint64(0),
			want:  8,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got := per.OctetsNonNegativeBinaryIntegerLength(tc.value)
				if got != tc.want {
					t.Errorf(
						"= %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}
}

// TestBitsTwosComplementBinaryInteger checks the bit width of clause 11.4.6.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestBitsTwosComplementBinaryInteger(t *testing.T) {
	cases := []struct {
		name  string
		value int64
		want  int
	}{
		{
			name:  "zero",
			value: 0,
			want:  1,
		},
		{
			name:  "one",
			value: 1,
			want:  2,
		},
		{
			name:  "three",
			value: 3,
			want:  3,
		},
		{
			name:  "four",
			value: 4,
			want:  4,
		},
		{
			name:  "minus_one",
			value: -1,
			want:  1,
		},
		{
			name:  "minus_two",
			value: -2,
			want:  2,
		},
		{
			name:  "minus_three",
			value: -3,
			want:  3,
		},
		{
			name:  "minus_four",
			value: -4,
			want:  3,
		},
		{
			name:  "minus_eight",
			value: -8,
			want:  4,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got := per.BitsTwosComplementBinaryInteger(tc.value)

				if got != tc.want {
					t.Errorf(
						"= %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}
}

// TestOctetsTwosComplementBinaryInteger checks the octet width of clause 11.4.6.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestOctetsTwosComplementBinaryInteger(t *testing.T) {
	cases := []struct {
		name  string
		value int64
		want  int
	}{
		{
			name:  "zero",
			value: 0,
			want:  1,
		},
		{
			name:  "max_one_octet",
			value: 127,
			want:  1,
		},
		{
			name:  "needs_two",
			value: 128,
			want:  2,
		},
		{
			name:  "max_two_octets",
			value: 32767,
			want:  2,
		},
		{
			name:  "needs_three",
			value: 32768,
			want:  3,
		},
		{
			name:  "max_int32",
			value: 2147483647,
			want:  4,
		},
		{
			name:  "max_int64",
			value: 9223372036854775807,
			want:  8,
		},
		{
			name:  "minus_one",
			value: -1,
			want:  1,
		},
		{
			name:  "min_one_octet",
			value: -128,
			want:  1,
		},
		{
			name:  "needs_two_negative",
			value: -129,
			want:  2,
		},
		{
			name:  "min_two_octets",
			value: -32768,
			want:  2,
		},
		{
			name:  "min_int32",
			value: -2147483648,
			want:  4,
		},
		{
			name:  "min_int64",
			value: -9223372036854775808,
			want:  8,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got := per.OctetsTwosComplementBinaryInteger(tc.value)

				if got != tc.want {
					t.Errorf(
						"= %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}
}

// TestCalculateFragmentSize checks the fragment multiplier of clause 11.9.3.8.1.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestCalculateFragmentSize(t *testing.T) {
	cases := []struct {
		name  string
		value uint64
		want  uint64
	}{
		{
			name:  "one_unit",
			value: per.FRAGMENT_SIZE,
			want:  per.FRAGMENT_SIZE,
		},
		{
			name:  "one_unit_and_more",
			value: per.FRAGMENT_SIZE + 1,
			want:  per.FRAGMENT_SIZE,
		},
		{
			name:  "two_units",
			value: 2 * per.FRAGMENT_SIZE,
			want:  2 * per.FRAGMENT_SIZE,
		},
		{
			name:  "four_units",
			value: 4 * per.FRAGMENT_SIZE,
			want:  4 * per.FRAGMENT_SIZE,
		},
		{
			name:  "capped",
			value: 100 * per.FRAGMENT_SIZE,
			want:  4 * per.FRAGMENT_SIZE,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got := per.CalculateFragmentSize(tc.value)

				if got != tc.want {
					t.Errorf(
						"= %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}
}

// TestMakeRealRoundTrip checks that a float64 survives decomposition and reassembly,
// with the odd mantissa clause 11.3.1 requires.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestMakeRealRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		value float64
	}{
		{
			name:  "pi",
			value: 3.14,
		},
		{
			name:  "one",
			value: 1,
		},
		{
			name:  "minus_one",
			value: -1,
		},
		{
			name:  "small",
			value: 1e-300,
		},
		{
			name:  "large",
			value: 1e300,
		},
		{
			name:  "half",
			value: 0.5,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				decomposed := per.MakeReal(tc.value)
				if got := decomposed.Float(); got != tc.value {
					t.Errorf(
						"round trip = %v, want %v",
						got,
						tc.value,
					)
				}

				if decomposed.Mantissa()%2 == 0 && decomposed.Mantissa() != 0 {
					t.Errorf(
						"mantissa %d is even, want odd",
						decomposed.Mantissa(),
					)
				}
			},
		)
	}
}
