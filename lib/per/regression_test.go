package per_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestRegressionBitStringShortBytes guards lib/review.md finding 1.1: a
// BitString whose Bytes cannot hold its BitLength is an error, where it used to
// index past the slice and panic.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionBitStringShortBytes(t *testing.T) {
	cases := []struct {
		name  string
		value *asn1.BitString
		size  *per.Constraint
	}{
		{
			name: "unconstrained",
			value: &asn1.BitString{
				Bytes:     []byte{0xFF},
				BitLength: 12,
			},
			size: per.Unconstrained(),
		},
		{
			name: "fixed_size",
			value: &asn1.BitString{
				Bytes:     []byte{0xFF},
				BitLength: 8,
			},
			size: per.Constrained(
				16,
				16,
			),
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				err := per.NewUnalignedEncoder().EncodeBitString(
					tc.value,
					tc.size,
				)
				if err == nil {
					t.Fatal("EncodeBitString() = nil, want an error")
				}
			},
		)
	}
}

// TestRegressionIntegerLengthOverflow guards lib/review.md finding 2.1: a length
// determinant wider than an integer is an error. Multiplying the octet count by
// eight into a uint8 wrapped, so 32 octets asked for zero bits and returned zero
// with no error, and 33 consumed one octet and desynchronised the stream.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionIntegerLengthOverflow(t *testing.T) {
	for _, octets := range []byte{0, 9, 32, 33, 64} {
		t.Run(
			_Name(
				"octets",
				octets,
			),
			func(t *testing.T) {
				var (
					data = append(
						[]byte{octets},
						bytes.Repeat(
							[]byte{0xFF},
							64,
						)...,
					)

					dec = per.NewUnalignedDecoder(data)

					_, err = dec.DecodeUnconstrainedWholeNumber()
				)
				if err == nil {
					t.Fatal(
						"DecodeUnconstrainedWholeNumber() = nil, " +
							"want an error",
					)
				}
			},
		)
	}
}

// TestRegressionIntegerOutOfRange guards lib/review.md finding 2.2: a value
// outside a non-extensible constraint is an error. The offset from the lower
// bound used to be truncated into a field sized for the range, so 9 in a type
// constrained to 0..7 encoded as 1.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionIntegerOutOfRange(t *testing.T) {
	cases := []struct {
		name  string
		value int64
		size  *per.Constraint
	}{
		{
			name:  "above_upper",
			value: 9,
			size: per.Constrained(
				0,
				7,
			),
		},
		{
			name:  "below_lower",
			value: -1,
			size: per.Constrained(
				0,
				7,
			),
		},
		{
			name:  "single_value",
			value: 6,
			size: per.Constrained(
				5,
				5,
			),
		},
		{
			name:  "below_semi",
			value: -1,
			size:  per.SemiConstrained(0),
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				err := per.NewUnalignedEncoder().EncodeInteger(
					tc.value,
					tc.size,
				)
				if !errors.Is(
					err,
					per.ErrValueOutOfRange,
				) {
					t.Errorf(
						"error = %v, want %v",
						err,
						per.ErrValueOutOfRange,
					)
				}
			},
		)
	}

	err := per.NewUnalignedEncoder().EncodeEnumerated(
		3,
		per.Constrained(
			0,
			2,
		),
	)
	if !errors.Is(
		err,
		per.ErrValueOutOfRange,
	) {
		t.Errorf(
			"EncodeEnumerated() error = %v, want %v",
			err,
			per.ErrValueOutOfRange,
		)
	}
}

// TestRegressionFixedSizeMismatch guards lib/review.md finding 2.3: a value
// whose length differs from a fixed size is an error. Such a value used to be
// written with no determinant, so the receiver read the constrained width out
// of whatever followed it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionFixedSizeMismatch(t *testing.T) {
	t.Run(
		"octet_string",
		func(t *testing.T) {
			var (
				size = per.Constrained(
					4,
					4,
				)

				err = per.NewUnalignedEncoder().EncodeOctetString(
					[]byte{1, 2},
					size,
				)
			)
			if !errors.Is(
				err,
				per.ErrLengthMismatch,
			) {
				t.Errorf(
					"error = %v, want %v",
					err,
					per.ErrLengthMismatch,
				)
			}
		},
	)

	t.Run(
		"bit_string",
		func(t *testing.T) {
			var (
				value = &asn1.BitString{
					Bytes:     []byte{0xFF, 0xFF},
					BitLength: 9,
				}

				err = per.NewUnalignedEncoder().EncodeBitString(
					value,
					per.Constrained(
						12,
						12,
					),
				)
			)
			if !errors.Is(
				err,
				per.ErrLengthMismatch,
			) {
				t.Errorf(
					"error = %v, want %v",
					err,
					per.ErrLengthMismatch,
				)
			}
		},
	)
}

// TestRegressionKnownMultiplierStrings guards lib/review.md finding 2.8: the
// known-multiplier character string types of X.691 clause 30.4 pack each
// character into the bits its alphabet needs, rather than a whole octet.
//
// Every expected value is Erlang asn1ct's for the same ASN.1 type and value.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionKnownMultiplierStrings(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		kind    per.StringKind
		size    *per.Constraint
		aligned bool
		want    []byte
	}{
		{
			name:    "ia5_uper",
			value:   "AB",
			kind:    per.STRING_IA5,
			size:    per.Unconstrained(),
			aligned: false,
			want:    []byte{0x02, 0x83, 0x08},
		},
		{
			name:    "visible_uper",
			value:   "AB",
			kind:    per.STRING_VISIBLE,
			size:    per.Unconstrained(),
			aligned: false,
			want:    []byte{0x02, 0x83, 0x08},
		},
		{
			name:    "printable_uper",
			value:   "AB",
			kind:    per.STRING_PRINTABLE,
			size:    per.Unconstrained(),
			aligned: false,
			want:    []byte{0x02, 0x83, 0x08},
		},
		{
			name:    "ia5_aper",
			value:   "AB",
			kind:    per.STRING_IA5,
			size:    per.Unconstrained(),
			aligned: true,
			want:    []byte{0x02, 0x41, 0x42},
		},
		{
			name:  "ia5_sized_uper",
			value: "AB",
			kind:  per.STRING_IA5,
			size: per.Constrained(
				1,
				10,
			),
			aligned: false,
			want:    []byte{0x18, 0x30, 0x80},
		},
		{
			name:  "ia5_sized_aper",
			value: "AB",
			kind:  per.STRING_IA5,
			size: per.Constrained(
				1,
				10,
			),
			aligned: true,
			want:    []byte{0x10, 0x41, 0x42},
		},
		{
			name:    "numeric_uper",
			value:   "12 3",
			kind:    per.STRING_NUMERIC,
			size:    per.Unconstrained(),
			aligned: false,
			want:    []byte{0x04, 0x23, 0x04},
		},
		{
			name:    "numeric_aper",
			value:   "12 3",
			kind:    per.STRING_NUMERIC,
			size:    per.Unconstrained(),
			aligned: true,
			want:    []byte{0x04, 0x23, 0x04},
		},
		{
			name:    "utf8_uper",
			value:   "AB",
			kind:    per.STRING_UTF8,
			size:    per.Unconstrained(),
			aligned: false,
			want:    []byte{0x02, 0x41, 0x42},
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				var (
					encoder = ENCODERS[tc.aligned]()

					err = encoder.EncodeRestrictedString(
						tc.value,
						tc.kind,
						tc.size,
					)
				)
				if err != nil {
					t.Fatalf(
						"EncodeRestrictedString: %v",
						err,
					)
				}

				got := encoder.Bytes()
				if !bytes.Equal(
					got,
					tc.want,
				) {
					t.Fatalf(
						"encoded % x, want % x",
						got,
						tc.want,
					)
				}

				back, err := DECODERS[tc.aligned](got).DecodeRestrictedString(
					tc.kind,
					tc.size,
				)
				if err != nil {
					t.Fatalf(
						"DecodeRestrictedString: %v",
						err,
					)
				}

				if back != tc.value {
					t.Errorf(
						"round trip = %q, want %q",
						back,
						tc.value,
					)
				}
			},
		)
	}
}

// TestRegressionAlphabetIsChecked guards the other half of finding 2.8: a
// character the type's alphabet does not contain is an error rather than a
// silently truncated bit-field.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionAlphabetIsChecked(t *testing.T) {
	err := per.NewUnalignedEncoder().
		EncodeRestrictedString(
			"12x3",
			per.STRING_NUMERIC,
			per.Unconstrained(),
		)
	if !errors.Is(
		err,
		per.ErrCharacterNotInAlphabet,
	) {
		t.Errorf(
			"error = %v, want %v",
			err,
			per.ErrCharacterNotInAlphabet,
		)
	}
}

// TestRegressionSizeUpperBoundOnly guards lib/review.md finding 2.9: a size
// constraint with only an upper bound has a lower bound of zero, per X.691
// clauses 16.4, 17.2 and 20.2. It used to be read as unconstrained.
//
// The expected values are Erlang asn1ct's for OCTET STRING (SIZE(0..10)).
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionSizeUpperBoundOnly(t *testing.T) {
	cases := []struct {
		name    string
		aligned bool
		want    []byte
	}{
		{
			name:    "uper",
			aligned: false,
			want:    []byte{0x26, 0x16, 0x20},
		},
		{
			name:    "aper",
			aligned: true,
			want:    []byte{0x20, 0x61, 0x62},
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				var (
					encoder = ENCODERS[tc.aligned]()

					err = encoder.EncodeOctetString(
						[]byte("ab"),
						per.Bounded(10),
					)
				)
				if err != nil {
					t.Fatalf(
						"EncodeOctetString: %v",
						err,
					)
				}

				got := encoder.Bytes()
				if !bytes.Equal(
					got,
					tc.want,
				) {
					t.Fatalf(
						"encoded % x, want % x",
						got,
						tc.want,
					)
				}

				back, err := DECODERS[tc.aligned](got).DecodeOctetString(
					per.Bounded(10),
				)
				if err != nil {
					t.Fatalf(
						"DecodeOctetString: %v",
						err,
					)
				}

				if !bytes.Equal(
					back,
					[]byte("ab"),
				) {
					t.Errorf(
						"round trip = % x, want % x",
						back,
						"ab",
					)
				}
			},
		)
	}
}

// TestRegressionRealMalformedIsAnError guards lib/review.md finding 2.7: a REAL
// whose contents octets are malformed is an error, where five paths used to
// return zero and no error, and a decimal encoding was read as a binary one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionRealMalformedIsAnError(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{
			name: "truncated_exponent",
			data: []byte{0x01, 0x81},
		},
		{
			name: "truncated_long_exponent",
			data: []byte{0x02, 0x83, 0x04},
		},
		{
			name: "reserved_base",
			data: []byte{0x03, 0xB0, 0x01, 0x01},
		},
		{
			name: "reserved_special",
			data: []byte{0x01, 0x4F},
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				var (
					dec = per.NewUnalignedDecoder(tc.data)

					_, err = dec.DecodeReal()
				)
				if err == nil {
					t.Error("DecodeReal() = nil, want an error")
				}
			},
		)
	}

	// X.690 clause 8.5.8 NR3, which used to be parsed as a binary encoding.
	t.Run(
		"decimal_nr3",
		func(t *testing.T) {
			var (
				data = append(
					[]byte{0x06, 0x03},
					[]byte("1.E+2")...,
				)

				got, err = per.NewUnalignedDecoder(data).DecodeReal()
			)
			if err != nil {
				t.Fatalf(
					"DecodeReal: %v",
					err,
				)
			}

			if got != 100 {
				t.Errorf(
					"DecodeReal() = %v, want 100",
					got,
				)
			}
		},
	)
}

// TestRegressionHexRoundTrip guards the SWAR hexadecimal conversions: the block
// form and the byte-at-a-time tail must agree with each other at every length,
// and the two directions must invert each other.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionHexRoundTrip(t *testing.T) {
	for size := range 40 {
		t.Run(
			_Name(
				"len",
				byte(size),
			),
			func(t *testing.T) {
				data := _Octets(uint64(size))
				for i := range data {
					data[i] = byte(i*37 + size)
				}

				text := per.BytesToHex(data)
				if len(text) != size*2 {
					t.Fatalf(
						"gave %d characters, want %d",
						len(text),
						size*2,
					)
				}

				if text != strings.ToLower(text) {
					t.Errorf(
						"BytesToHex gave %q, want lowercase",
						text,
					)
				}

				back, err := per.HexToBytes(text)
				if err != nil {
					t.Fatalf(
						"HexToBytes: %v",
						err,
					)
				}

				if !bytes.Equal(
					back,
					data,
				) {
					t.Errorf(
						"round trip = % x, want % x",
						back,
						data,
					)
				}

				upper, err := per.HexToBytes(strings.ToUpper(text))
				if err != nil {
					t.Fatalf(
						"HexToBytes upper: %v",
						err,
					)
				}

				if !bytes.Equal(
					upper,
					data,
				) {
					t.Errorf(
						"upper case round trip = % x, want % x",
						upper,
						data,
					)
				}
			},
		)
	}
}

// TestRegressionHexRejectsBadInput guards the validity check the block form
// folds into one test.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionHexRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		text string
		want error
	}{
		{
			name: "odd_length",
			text: "abc",
			want: per.ErrOddHexLength,
		},
		{
			name: "bad_in_block",
			text: "0123456x89abcdef",
			want: per.ErrInvalidHex,
		},
		{
			name: "bad_in_tail",
			text: "0123456789abcdefzz",
			want: per.ErrInvalidHex,
		},
		{
			name: "bad_short",
			text: "zz",
			want: per.ErrInvalidHex,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				if _, err := per.HexToBytes(tc.text); !errors.Is(
					err,
					tc.want,
				) {
					t.Errorf(
						"error = %v, want %v",
						err,
						tc.want,
					)
				}
			},
		)
	}
}

// TestRegressionBinaryStringRoundTrip guards the SWAR bit string conversions,
// which replaced a loop that appended one character to a string per bit.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-21 21:38: FormatBitString and ParseBitString (review P31)
func TestRegressionBinaryStringRoundTrip(t *testing.T) {
	for length := range 130 {
		t.Run(
			_Name(
				"bits",
				byte(length%256),
			),
			func(t *testing.T) {
				var (
					want = _Bitstring(uint64(length))

					text, err = per.FormatBitString(want)
				)
				if err != nil || len(text) != length {
					t.Fatalf(
						"gave %d characters, %v; want %d",
						len(text),
						err,
						length,
					)
				}

				got, err := per.ParseBitString(text)
				if err != nil {
					t.Fatalf(
						"ParseBitString: %v",
						err,
					)
				}

				if got.BitLength != want.BitLength {
					t.Fatalf(
						"BitLength = %d, want %d",
						got.BitLength,
						want.BitLength,
					)
				}

				if !bytes.Equal(
					got.Bytes,
					want.Bytes,
				) {
					t.Errorf(
						"Bytes = % x, want % x",
						got.Bytes,
						want.Bytes,
					)
				}
			},
		)
	}

	if _, err := per.ParseBitString("0101x101"); !errors.Is(
		err,
		per.ErrInvalidBinary,
	) {
		t.Errorf(
			"error = %v, want %v",
			err,
			per.ErrInvalidBinary,
		)
	}
}

// _Name builds a subtest _Name from a label and a number.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Name(
	label string,
	value byte,
) string {
	// strconv would do, but three digits is all a subtest name needs.
	return label + "_" + string(rune('0'+value/100%10)) +
		string(rune('0'+value/10%10)) + string(rune('0'+value%10))
}
