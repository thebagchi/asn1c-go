package per_test

import (
	"errors"
	"math"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

type _P4Unsigned struct {
	_P4Oracles
	Type  string  `json:"type"`
	Lb    uint64  `json:"lb"`
	Ub    *uint64 `json:"ub"`
	Value uint64  `json:"value"`
}

type _P4UnsignedFile struct {
	Unsigned []*_P4Unsigned `json:"unsigned"`
}

// TestUnsigned_Vectors checks EncodeUnsigned against the octets of pycrate and
// OTP (testing/unsigned.py), and DecodeUnsigned against the same octets. The
// ranges follow X.691 clause 11.5 (constrained whole number, including the range
// of 2^64 values for 0..2^64-1) and clause 11.7 (semi-constrained, 0..MAX and
// 2^63..MAX). A range of one value (1000..1000) has no bits (11.5.4).
//
// Revisions:
//   - 2026-10-19 11:32: initial creation
func TestUnsigned_Vectors(t *testing.T) {
	var file _P4UnsignedFile

	_Load(
		t,
		VECTOR_UNSIGNED,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.Unsigned {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.Type+"_"+_Show(&tc.Value),
				func(t *testing.T) {
					var (
						want = _Unhex(
							t,
							_Both(
								tc.Aper,
								tc.Uper,
							)[aligned],
						)
						root = _UnsignedRoot(tc)

						enc = ENCODERS[aligned]()
					)
					if err := enc.EncodeUnsigned(
						tc.Value,
						root,
					); err != nil {
						t.Fatalf(
							"EncodeUnsigned() = %v",
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						want,
					)

					got, err := DECODERS[aligned](want).DecodeUnsigned(root)
					if err != nil {
						t.Fatalf(
							"DecodeUnsigned() = %v",
							err,
						)
					}

					if got != tc.Value {
						t.Fatalf(
							"decode = %d, want %d",
							got,
							tc.Value,
						)
					}
				},
			)
		}
	}
}

// TestUnsigned_Framed writes each vector value between BOOLEAN fields and reads
// it back. The decoder must stop at the last bit of the value and keep the
// ALIGNED padding of clauses 11.5.7 and 11.7.
//
// Revisions:
//   - 2026-10-19 11:32: initial creation
func TestUnsigned_Framed(t *testing.T) {
	var file _P4UnsignedFile

	_Load(
		t,
		VECTOR_UNSIGNED,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.Unsigned {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.Type+"_"+_Show(&tc.Value),
				func(t *testing.T) {
					root := _UnsignedRoot(tc)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeUnsigned(
								tc.Value,
								root,
							)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeUnsigned(root)
							if err == nil && got != tc.Value {
								t.Errorf(
									"decode = %d, want %d",
									got,
									tc.Value,
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

// TestUnsigned_OutOfRange checks that a value outside the constraint has no
// encoding (X.691 clauses 11.5.3 and 11.7: the value is in the range of the
// type) and that the encoder says so with ErrValueOutOfRange. The control case
// is a value inside the range.
//
// Revisions:
//   - 2026-10-19 11:32: initial creation
func TestUnsigned_OutOfRange(t *testing.T) {
	cases := []struct {
		name  string
		root  *per.UnsignedConstraint
		value uint64
		valid bool
	}{
		{
			name: "control_in_range",
			root: per.Unsigned(
				10,
				20,
			),
			value: 15,
			valid: true,
		},
		{
			name: "below_lb",
			root: per.Unsigned(
				10,
				20,
			),
			value: 9,
		},
		{
			name: "above_ub",
			root: per.Unsigned(
				10,
				20,
			),
			value: 21,
		},
		{
			name: "single_below",
			root: per.Unsigned(
				1000,
				1000,
			),
			value: 999,
		},
		{
			name: "single_above",
			root: per.Unsigned(
				1000,
				1000,
			),
			value: 1001,
		},
		{
			name: "zero_below_lb",
			root: per.Unsigned(
				1,
				math.MaxUint64,
			),
			value: 0,
		},
		{
			name: "high_below_lb",
			root: per.Unsigned(
				1<<63,
				math.MaxUint64,
			),
			value: 1<<63 - 1,
		},
		{
			name: "high_zero",
			root: per.Unsigned(
				1<<63,
				math.MaxUint64,
			),
			value: 0,
		},
		{
			name: "above_ub_byte",
			root: per.Unsigned(
				0,
				255,
			),
			value: 256,
		},
		{
			name: "above_ub_max_minus_one",
			root: per.Unsigned(
				0,
				math.MaxUint64-1,
			),
			value: math.MaxUint64,
		},
		{
			name:  "semi_below_lb",
			root:  per.SemiUnsigned(100),
			value: 99,
		},
		{
			name:  "semi_high_below_lb",
			root:  per.SemiUnsigned(1 << 63),
			value: 1<<63 - 1,
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					err := ENCODERS[aligned]().EncodeUnsigned(
						tc.value,
						tc.root,
					)

					if tc.valid {
						if err != nil {
							t.Fatalf(
								"EncodeUnsigned() = %v",
								err,
							)
						}

						return
					}

					if !errors.Is(
						err,
						per.ErrValueOutOfRange,
					) {
						t.Fatalf(
							"error = %v, want %v",
							err,
							per.ErrValueOutOfRange,
						)
					}
				},
			)
		}
	}
}

// TestUnsigned_DecodeMalformed checks inputs that no encoder writes. An offset
// above the range of the constraint is a malformed encoding (X.691 clause 13.2
// and 11.5.6: the field holds 2^n values and the range need not). It is
// ErrValueOutOfRange. A semi-constrained value that does not fit in 64 bits,
// and input that ends early, are errors too. The control case is a valid
// encoding.
//
// Revisions:
//   - 2026-10-19 11:32: initial creation
func TestUnsigned_DecodeMalformed(t *testing.T) {
	cases := []struct {
		name    string
		aligned bool
		data    []byte
		root    *per.UnsignedConstraint
		want    error
		valid   bool
	}{
		{
			name:    "control_uper_byte_range",
			aligned: false,
			data:    []byte{0xC8},
			root: per.Unsigned(
				0,
				200,
			),
			valid: true,
		},
		{
			name:    "uper_offset_201_in_0_200",
			aligned: false,
			data:    []byte{0xC9},
			root: per.Unsigned(
				0,
				200,
			),
			want: per.ErrValueOutOfRange,
		},
		{
			name:    "aper_offset_255_in_0_200",
			aligned: true,
			data:    []byte{0xFF},
			root: per.Unsigned(
				0,
				200,
			),
			want: per.ErrValueOutOfRange,
		},
		{
			name:    "uper_offset_15_in_10_20",
			aligned: false,
			data:    []byte{0xF0},
			root: per.Unsigned(
				10,
				20,
			),
			want: per.ErrValueOutOfRange,
		},
		{
			name:    "aper_offset_65535_in_0_300",
			aligned: true,
			data:    []byte{0xFF, 0xFF},
			root: per.Unsigned(
				0,
				300,
			),
			want: per.ErrValueOutOfRange,
		},
		{
			name:    "uper_offset_511_in_0_300",
			aligned: false,
			data:    []byte{0xFF, 0x80},
			root: per.Unsigned(
				0,
				300,
			),
			want: per.ErrValueOutOfRange,
		},
		{
			name:    "uper_offset_above_in_high_range",
			aligned: false,
			data:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			root: per.Unsigned(
				1<<63,
				1<<63+5,
			),
			want: per.ErrValueOutOfRange,
		},
		{
			name:    "uper_empty_input",
			aligned: false,
			data:    []byte{},
			root: per.Unsigned(
				0,
				255,
			),
		},
		{
			name:    "aper_truncated_full_range",
			aligned: true,
			data:    []byte{0xE0, 0xFF},
			root: per.Unsigned(
				0,
				math.MaxUint64,
			),
		},
		{
			name:    "semi_truncated",
			aligned: false,
			data:    []byte{0x08, 0xFF},
			root:    per.SemiUnsigned(0),
		},
		{
			name:    "semi_length_nine",
			aligned: false,
			data:    []byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},
			root:    per.SemiUnsigned(0),
		},
		{
			name:    "semi_high_overflow",
			aligned: false,
			data:    []byte{0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			root:    per.SemiUnsigned(1 << 63),
		},
		{
			name:    "semi_high_overflow_min",
			aligned: true,
			data:    []byte{0x08, 0x80, 0, 0, 0, 0, 0, 0, 0},
			root:    per.SemiUnsigned(1 << 63),
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				_, err := DECODERS[tc.aligned](tc.data).DecodeUnsigned(tc.root)

				switch {
				case tc.valid:
					if err != nil {
						t.Fatalf(
							"DecodeUnsigned() = %v",
							err,
						)
					}
				case tc.want != nil:
					if !errors.Is(
						err,
						tc.want,
					) {
						t.Fatalf(
							"error = %v, want %v",
							err,
							tc.want,
						)
					}
				default:
					if err == nil {
						t.Fatalf("error = nil, want an error")
					}
				}
			},
		)
	}
}

// TestUnsigned_DecodeMalformedControl is the control of the two refusal tests: a
// valid encoding of the same constraints decodes. A stub that always fails does
// not pass TestUnsigned_DecodeMalformed on its error cases alone.
//
// Revisions:
//   - 2026-10-19 11:32: initial creation
func TestUnsigned_DecodeMalformedControl(t *testing.T) {
	cases := []struct {
		name    string
		aligned bool
		data    []byte
		root    *per.UnsignedConstraint
		want    uint64
	}{
		{
			name:    "semi_high_lb",
			aligned: false,
			data:    []byte{0x01, 0x00},
			root:    per.SemiUnsigned(1 << 63),
			want:    1 << 63,
		},
		{
			name:    "semi_high_top",
			aligned: true,
			data:    []byte{0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			root:    per.SemiUnsigned(1 << 63),
			want:    math.MaxUint64,
		},
		{
			name:    "aper_byte_range_top",
			aligned: true,
			data:    []byte{0xFF},
			root: per.Unsigned(
				0,
				255,
			),
			want: 255,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got, err := DECODERS[tc.aligned](tc.data).DecodeUnsigned(tc.root)
				if err != nil {
					t.Fatalf(
						"DecodeUnsigned() = %v",
						err,
					)
				}

				if got != tc.want {
					t.Fatalf(
						"decode = %d, want %d",
						got,
						tc.want,
					)
				}
			},
		)
	}
}

// _UnsignedRoot builds the constraint a vector row describes.
//
// Revisions:
//   - 2026-10-19 11:32: initial creation
func _UnsignedRoot(row *_P4Unsigned) *per.UnsignedConstraint {
	if row.Ub == nil {
		return per.SemiUnsigned(row.Lb)
	}

	return per.Unsigned(
		row.Lb,
		*row.Ub,
	)
}
