package per_test

import (
	"encoding/asn1"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_NAMEDBITS is the kind key in testing.json of testing/namedbits.py, which asks pycrate
// 0.8.1
// and Erlang/OTP 29.1.1 for every expected octet in it.
const (
	VECTOR_NAMEDBITS = "namedbits"
)

type _P6Row struct {
	_P4Oracles
	Type        string  `json:"type"`
	Lb          *int64  `json:"lb"`
	Ub          *int64  `json:"ub"`
	Ext         bool    `json:"ext"`
	Bits        string  `json:"bits"`
	Transmitted *string `json:"transmitted"`
}

type _P6File struct {
	NamedBits []*_P6Row `json:"namedbits"`
}

// _P6Size builds the size constraint of a row: no bounds, SIZE(lb..ub), or the
// same with an extension marker.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func _P6Size(row *_P6Row) *per.Constraint {
	var size *per.Constraint

	if row.Lb != nil && row.Ub != nil {
		size = per.Constrained(
			*row.Lb,
			*row.Ub,
		)
	} else {
		size = per.Unconstrained()
	}

	if row.Ext {
		size = size.Extensible()
	}

	return size
}

// _P6Value packs a text of 0 and 1 into a BitString, leading bit first, with 0
// bits as padding in the last octet (X.680 22.2).
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func _P6Value(bits string) *asn1.BitString {
	value := &asn1.BitString{
		Bytes: make(
			[]byte,
			(len(bits)+7)/8,
		),
		BitLength: len(bits),
	}

	for index, bit := range []byte(bits) {
		if bit == '1' {
			value.Bytes[index/8] |= 0x80 >> (index % 8)
		}
	}

	return value
}

// _P6Text is the inverse of _P6Value for the BitLength bits of a value.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func _P6Text(value *asn1.BitString) string {
	text := make(
		[]byte,
		value.BitLength,
	)

	for index := range text {
		text[index] = byte('0' + value.At(index))
	}

	return string(text)
}

// _P6Trim removes the trailing 0 bits of a text of 0 and 1. X.680 22.7 makes
// two values equal when they differ only in these bits.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func _P6Trim(text string) string {
	end := len(text)
	for end > 0 && text[end-1] == '0' {
		end--
	}

	return text[:end]
}

// _P6Name names a row for a subtest.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func _P6Name(row *_P6Row) string {
	return row.Type + "_" + row.Bits
}

// TestNamedBitString_Vectors checks EncodeNamedBitString against the octets of
// pycrate and OTP (testing/namedbits.py) for the type BIT STRING {a(0), b(1),
// c(2), d(5), e(9)} with no SIZE, SIZE(8), SIZE(4..12), SIZE(0..20),
// SIZE(2..7,...) and SIZE(16..32). The value given to the encoder is the
// untrimmed one, with trailing 0 bits of any number: X.691 16.2 asks for none
// in the transmitted value when no PER-visible size constraint applies, and
// 16.3 for the smallest size that carries the value and satisfies the effective
// size constraint, so 0 bits are also added up to the lower bound. A value
// whose last 1 bit lies beyond the upper bound has no such size: under an
// extension marker it goes outside the extension root (16.6), and without one
// it is refused (rows with transmitted null). DecodeBitString reads the
// transmitted bits, and X.680 22.7 makes the value it returns equal to the
// input when both are trimmed. OTP trims and pads itself; pycrate 0.8.1 does
// not, so it was given the transmitted value. The two agree on every row.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func TestNamedBitString_Vectors(t *testing.T) {
	var file _P6File

	_Load(
		t,
		VECTOR_NAMEDBITS,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.NamedBits {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P6Name(tc),
				func(t *testing.T) {
					var (
						size = _P6Size(tc)
						in   = _P6Value(tc.Bits)
						enc  = ENCODERS[aligned]()
						err  = enc.EncodeNamedBitString(
							in,
							size,
						)
					)

					if tc.Transmitted == nil {
						if err == nil {
							t.Fatalf(
								"Encode(%q) = nil, want error",
								tc.Bits,
							)
						}

						return
					}

					if err != nil {
						t.Fatalf(
							"EncodeNamedBitString(%q) = %v",
							tc.Bits,
							err,
						)
					}

					want := _Unhex(
						t,
						_Both(
							tc.Aper,
							tc.Uper,
						)[aligned],
					)

					_Compare(
						t,
						enc.Bytes(),
						want,
					)

					got, err := DECODERS[aligned](want).DecodeBitString(size)
					if err != nil {
						t.Fatalf(
							"DecodeBitString() = %v",
							err,
						)
					}

					if text := _P6Text(got); text != *tc.Transmitted {
						t.Fatalf(
							"decoded %q, transmitted bits are %q",
							text,
							*tc.Transmitted,
						)
					}

					if _P6Trim(_P6Text(got)) != _P6Trim(tc.Bits) {
						t.Fatalf(
							"decoded %q, want %q (X.680 22.7)",
							_P6Text(got),
							tc.Bits,
						)
					}
				},
			)
		}
	}
}

// TestNamedBitString_Canonical checks that the value as transmitted gives the
// same octets as the untrimmed value: the encoder removes and adds trailing 0
// bits itself (X.691 16.2, 16.3), so a caller that trimmed already, or never
// trimmed, gets one encoding.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func TestNamedBitString_Canonical(t *testing.T) {
	var file _P6File

	_Load(
		t,
		VECTOR_NAMEDBITS,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.NamedBits {
			if tc.Transmitted == nil {
				continue
			}

			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P6Name(tc),
				func(t *testing.T) {
					var (
						size = _P6Size(tc)
						enc  = ENCODERS[aligned]()
					)

					if err := enc.EncodeNamedBitString(
						_P6Value(*tc.Transmitted),
						size,
					); err != nil {
						t.Fatalf(
							"EncodeNamedBitString(%q) = %v",
							*tc.Transmitted,
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						_Unhex(
							t,
							_Both(
								tc.Aper,
								tc.Uper,
							)[aligned],
						),
					)
				},
			)
		}
	}
}

// TestNamedBitString_Framed writes each valid vector value between BOOLEAN
// fields, so a codec that stops one bit early or late, or pads wrongly (X.691
// 16.6 to 16.11, and 11.9 for the length), shows in the next field.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func TestNamedBitString_Framed(t *testing.T) {
	var file _P6File

	_Load(
		t,
		VECTOR_NAMEDBITS,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.NamedBits {
			if tc.Transmitted == nil {
				continue
			}

			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P6Name(tc),
				func(t *testing.T) {
					var (
						size = _P6Size(tc)
						in   = _P6Value(tc.Bits)
					)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeNamedBitString(
								in,
								size,
							)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeBitString(size)
							if err != nil {
								return err
							}

							if _P6Text(got) != *tc.Transmitted {
								t.Errorf(
									"decode = %q, want %q",
									_P6Text(got),
									*tc.Transmitted,
								)
							}

							return nil
						},
					)
				},
			)
		}
	}
}

// TestNamedBitString_EncodeRefused checks inputs that have no encoding. A nil
// value, and a BitString with fewer octets than its BitLength claims, are not
// values. A value with a 1 bit beyond the upper bound is refused when the type
// has no extension marker (X.691 16.3: no size carries it and satisfies SIZE).
// The control cases are valid, so a stub that always fails cannot pass.
//
// Revisions:
//   - 2026-10-19 13:36: initial creation
func TestNamedBitString_EncodeRefused(t *testing.T) {
	cases := []struct {
		name  string
		value *asn1.BitString
		size  *per.Constraint
		valid bool
	}{
		{
			name:  "control_trailing_zeros_trimmed_to_fit",
			value: _P6Value("1000000000000000000000000"),
			size: per.Constrained(
				0,
				20,
			),
			valid: true,
		},
		{
			name:  "control_extensible_outside_root",
			value: _P6Value("0000000000000001"),
			size: per.Constrained(
				2,
				7,
			).Extensible(),
			valid: true,
		},
		{
			name:  "control_nil_size",
			value: _P6Value("101"),
			size:  nil,
			valid: true,
		},
		{
			name:  "nil_value",
			value: nil,
			size:  per.Unconstrained(),
		},
		{
			name: "short_bytes",
			value: &asn1.BitString{
				Bytes:     []byte{0x80},
				BitLength: 16,
			},
			size: per.Unconstrained(),
		},
		{
			name:  "last_one_beyond_ub",
			value: _P6Value("0000000000100000"),
			size: per.Constrained(
				0,
				8,
			),
		},
		{
			name:  "last_one_just_beyond_ub",
			value: _P6Value("000000001"),
			size: per.Constrained(
				8,
				8,
			),
		},
		{
			name:  "last_one_beyond_ub_range",
			value: _P6Value("0000000000001"),
			size: per.Constrained(
				4,
				12,
			),
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					err := ENCODERS[aligned]().EncodeNamedBitString(
						tc.value,
						tc.size,
					)

					if tc.valid {
						if err != nil {
							t.Fatalf(
								"EncodeNamedBitString() = %v",
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
