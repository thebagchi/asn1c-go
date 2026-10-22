package per_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestRegression_P11NormallySmallWide guards review P13-1, which closes P11-2.
// X.691 11.6 sends a normally small number of 64 or more as a 1 bit followed by
// the semi-constrained form of X.691 11.7.
// In ALIGNED PER the 1 bit is followed by seven pad bits, so the octets start with 80.
// DecodeNormallySmallNonNegativeWholeNumber returns a raw uint64.
// An offset above int64 is therefore valid.
// DecodeSemiConstrainedWholeNumber(0) returns an int64 and must refuse the same two bodies.
// The row value_64 is a control, and it passes on the code before the change.
//
// Revisions:
//   - 2026-10-20 01:24: initial creation
func TestRegression_P11NormallySmallWide(t *testing.T) {
	var (
		wide = []byte{
			0x08,
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
		}
		full = []byte{
			0x08,
			0xFF,
			0xFF,
			0xFF,
			0xFF,
			0xFF,
			0xFF,
			0xFF,
			0xFF,
		}

		cases = []struct {
			name string
			data []byte
			want uint64
		}{
			{
				name: "value_64",
				data: []byte{
					0x80,
					0x01,
					0x40,
				},
				want: 64,
			},
			{
				name: "value_2_pow_63",
				data: append(
					[]byte{0x80},
					wide...,
				),
				want: 1 << 63,
			},
			{
				name: "value_2_pow_64_minus_1",
				data: append(
					[]byte{0x80},
					full...,
				),
				want: ^uint64(0),
			},
		}
	)

	for _, tc := range cases {
		t.Run(
			"normally_small_"+tc.name,
			func(t *testing.T) {
				var (
					dec = per.NewAlignedDecoder(tc.data)

					got, err = dec.DecodeNormallySmallNonNegativeWholeNumber()
				)
				if err != nil {
					t.Fatalf(
						"error: %v",
						err,
					)
				}

				if got != tc.want {
					t.Fatalf(
						"got %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}

	refused := []struct {
		name string
		data []byte
	}{
		{
			name: "offset_2_pow_63",
			data: wide,
		},
		{
			name: "offset_2_pow_64_minus_1",
			data: full,
		},
	}

	for _, tc := range refused {
		t.Run(
			"semi_constrained_"+tc.name,
			func(t *testing.T) {
				var (
					dec = per.NewAlignedDecoder(tc.data)

					got, err = dec.DecodeSemiConstrainedWholeNumber(0)
				)
				if !errors.Is(
					err,
					per.ErrValueOutOfRange,
				) {
					t.Fatalf(
						"got %d, error %v, want ErrValueOutOfRange",
						got,
						err,
					)
				}
			},
		)
	}
}

// _P11Bits builds the BIT STRING of a row from octets and a bit count.
//
// Revisions:
//   - 2026-10-20 01:24: initial creation
func _P11Bits(
	data []byte,
	length int,
) *asn1.BitString {
	return &asn1.BitString{
		Bytes:     data,
		BitLength: length,
	}
}

// TestRegression_P11BitStringAlign guards reviews P11-3 and P14-1.
// T is SEQUENCE { b BOOLEAN TRUE, s BIT STRING (SIZE (0..8)) }, written as EncodeBoolean
// and then EncodeBitString with Constrained(0, 8).
// X.691 16.11 puts a bit string of more than zero bits in an octet-aligned field in the
// ALIGNED variant, and X.691 11.9.3.3 appends that field only when the length is not zero.
// The want octets come from pycrate 0.8.1 and OTP 29.1.1. Review P14-1 records them, and the
// reviewer accepted them there.
//
// Revisions:
//   - 2026-10-20 01:24: initial creation
func TestRegression_P11BitStringAlign(t *testing.T) {
	var (
		cases = []struct {
			name string
			bits *asn1.BitString
			aper []byte
			uper []byte
		}{
			{
				name: "zero_bits",
				bits: _P11Bits(
					nil,
					0,
				),
				aper: []byte{0x80},
				uper: []byte{0x80},
			},
			{
				name: "one_bit",
				bits: _P11Bits(
					[]byte{0x80},
					1,
				),
				aper: []byte{
					0x88,
					0x80,
				},
				uper: []byte{0x8C},
			},
			{
				name: "five_bits",
				bits: _P11Bits(
					[]byte{0xA8},
					5,
				),
				aper: []byte{
					0xA8,
					0xA8,
				},
				uper: []byte{
					0xAD,
					0x40,
				},
			},
			{
				name: "eight_bits",
				bits: _P11Bits(
					[]byte{0xFF},
					8,
				),
				aper: []byte{
					0xC0,
					0xFF,
				},
				uper: []byte{
					0xC7,
					0xF8,
				},
			},
		}

		variants = []struct {
			name    string
			aligned bool
		}{
			{
				name:    "aper",
				aligned: true,
			},
			{
				name:    "uper",
				aligned: false,
			},
		}
	)

	for _, variant := range variants {
		for _, tc := range cases {
			want := tc.uper
			if variant.aligned {
				want = tc.aper
			}

			t.Run(
				variant.name+"_"+tc.name,
				func(t *testing.T) {
					got := _P11EncodeSequence(
						t,
						ENCODERS[variant.aligned](),
						tc.bits,
					)
					if !bytes.Equal(
						got,
						want,
					) {
						t.Fatalf(
							"got %x, want %x",
							got,
							want,
						)
					}

					_P11DecodeSequence(
						t,
						DECODERS[variant.aligned](got),
						tc.bits,
					)
				},
			)
		}
	}
}

// _P11EncodeSequence writes T with the primitives and returns the octets.
//
// Revisions:
//   - 2026-10-20 01:26: initial creation
func _P11EncodeSequence(
	t *testing.T,
	enc *per.Encoder,
	bits *asn1.BitString,
) []byte {
	t.Helper()

	err := enc.EncodeBoolean(true)
	if err != nil {
		t.Fatalf(
			"EncodeBoolean: %v",
			err,
		)
	}

	err = enc.EncodeBitString(
		bits,
		per.Constrained(
			0,
			8,
		),
	)
	if err != nil {
		t.Fatalf(
			"EncodeBitString: %v",
			err,
		)
	}

	return enc.Bytes()
}

// _P11DecodeSequence reads T again and compares the bit string with want.
//
// Revisions:
//   - 2026-10-20 01:26: initial creation
func _P11DecodeSequence(
	t *testing.T,
	dec *per.Decoder,
	want *asn1.BitString,
) {
	t.Helper()

	flag, err := dec.DecodeBoolean()
	if err != nil {
		t.Fatalf(
			"DecodeBoolean: %v",
			err,
		)
	}

	if !flag {
		t.Fatalf("boolean is false, want true")
	}

	back, err := dec.DecodeBitString(per.Constrained(
		0,
		8,
	))
	if err != nil {
		t.Fatalf(
			"DecodeBitString: %v",
			err,
		)
	}

	if back.BitLength != want.BitLength {
		t.Fatalf(
			"bit length %d, want %d",
			back.BitLength,
			want.BitLength,
		)
	}

	if !bytes.Equal(
		back.Bytes,
		want.Bytes,
	) {
		t.Fatalf(
			"bits %x, want %x",
			back.Bytes,
			want.Bytes,
		)
	}
}
