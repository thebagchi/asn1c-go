package per_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_REGRESSION is the kind key in testing.json of testing/regression.py, which asks pycrate
// 0.8.1 for every expected octet in it.
const (
	VECTOR_REGRESSION = "regression"
)

// VARIANT_NAMES names the PER variant for a subtest.
var (
	VARIANT_NAMES = map[bool]string{
		true:  "aper",
		false: "uper",
	}
)

type _P3Integer struct {
	Type  string `json:"type"`
	Value int64  `json:"value"`
	Lb    int64  `json:"lb"`
	Ub    int64  `json:"ub"`
	Aper  string `json:"aper"`
	Uper  string `json:"uper"`
}

type _P3String struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Lb    *int64 `json:"lb"`
	Ub    *int64 `json:"ub"`
	Aper  string `json:"aper"`
	Uper  string `json:"uper"`
}

type _P3Empty struct {
	Type string `json:"type"`
	Aper string `json:"aper"`
	Uper string `json:"uper"`
}

type _P3File struct {
	Integers []*_P3Integer `json:"integers"`
	Strings  []*_P3String  `json:"strings"`
	Empty    []*_P3Empty   `json:"empty"`
}

// TestRegression_P3SizeOutOfRange guards lib/review.md item P3-1. X.691 clause
// 11.9.3.3 gives a length that lies outside the SIZE constraint no encoding, so
// the encoder refuses it. EncodeLengthDeterminant masked the length to the
// width of the field, so 20 octets in SIZE(0..10) were written as 4.
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func TestRegression_P3SizeOutOfRange(t *testing.T) {
	cases := []struct {
		name   string
		encode func(enc *per.Encoder) error
	}{
		{
			name: "length_determinant_above",
			encode: func(enc *per.Encoder) error {
				_, err := enc.EncodeLengthDeterminant(
					20,
					per.Constrained(
						0,
						10,
					),
				)

				return err
			},
		},
		{
			name: "length_determinant_below",
			encode: func(enc *per.Encoder) error {
				_, err := enc.EncodeLengthDeterminant(
					1,
					per.Constrained(
						2,
						10,
					),
				)

				return err
			},
		},
		{
			name: "octet_string_above",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeOctetString(
					bytes.Repeat(
						[]byte{0xA5},
						20,
					),
					per.Constrained(
						0,
						10,
					),
				)
			},
		},
		{
			name: "octet_string_below",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeOctetString(
					[]byte{0xA5},
					per.Constrained(
						2,
						10,
					),
				)
			},
		},
		{
			name: "bit_string_above",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeBitString(
					&asn1.BitString{
						Bytes: bytes.Repeat(
							[]byte{0xA5},
							3,
						),
						BitLength: 20,
					},
					per.Constrained(
						0,
						10,
					),
				)
			},
		},
		{
			name: "ia5_string_above",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeRestrictedString(
					"abcdef",
					per.STRING_IA5,
					per.Constrained(
						1,
						4,
					),
				)
			},
		},
		{
			name: "ia5_string_below",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeRestrictedString(
					"",
					per.STRING_IA5,
					per.Constrained(
						1,
						4,
					),
				)
			},
		},
		{
			name: "octet_string_above_64k",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeOctetString(
					bytes.Repeat(
						[]byte{0xA5},
						70001,
					),
					per.Constrained(
						0,
						70000,
					),
				)
			},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					err := tc.encode(ENCODERS[aligned]())
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

// TestRegression_P3SizeOutOfRangeDecode guards lib/review.md item P3-1, decoder
// side. A length field that names more than the upper bound is a malformed
// encoding (X.691 clause 11.9.3.3). The 4-bit field of SIZE(0..10) can hold 11
// to 15, and the semi-constrained length of SIZE(0..70000) can hold any number.
// The input octets here are crafted, not an encoding. The 70001 octets of the
// last case are fragmented (clause 11.9.3.8): 0xC4 (four 16K blocks), 65536
// octets, then 0x91 0x71 (the two-octet form, 0x9171 & 0x3FFF = 4465) and 4465
// octets. The guard test below decodes the same input under SIZE(0..80000).
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
//   - 2026-10-19 11:16: the 70001 input is fragmented, where the first form
//     was a valid length of 4465
func TestRegression_P3SizeOutOfRangeDecode(t *testing.T) {
	cases := []struct {
		name    string
		aligned bool
		data    []byte
		size    *per.Constraint
	}{
		{
			name:    "octet_string_uper_length_15",
			aligned: false,
			data: append(
				[]byte{0xF0},
				bytes.Repeat(
					[]byte{0xFF},
					16,
				)...,
			),
			size: per.Constrained(
				0,
				10,
			),
		},
		{
			name:    "octet_string_aper_length_15",
			aligned: true,
			data: append(
				[]byte{0xF0},
				bytes.Repeat(
					[]byte{0xFF},
					16,
				)...,
			),
			size: per.Constrained(
				0,
				10,
			),
		},
		{
			name:    "octet_string_aper_above_64k",
			aligned: true,
			data:    _Fragmented70001(),
			size: per.Constrained(
				0,
				70000,
			),
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				_, err := DECODERS[tc.aligned](tc.data).DecodeOctetString(tc.size)
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

// TestRegression_P3RangeOverflow guards lib/review.md item P3-2. X.691 clause
// 11.5.3 takes the range as ub - lb + 1, and for INTEGER (-2^63..2^63-1) that
// is 2^64, which an int64 wraps to zero. The expected octets come from pycrate
// (testing/regression.py).
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func TestRegression_P3RangeOverflow(t *testing.T) {
	var file _P3File

	_Load(
		t,
		VECTOR_REGRESSION,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.Integers {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.Type+"_"+_Show(&tc.Value),
				func(t *testing.T) {
					var (
						size = per.Constrained(
							tc.Lb,
							tc.Ub,
						)
						want = _Unhex(
							t,
							_Both(
								tc.Aper,
								tc.Uper,
							)[aligned],
						)

						enc = ENCODERS[aligned]()
					)

					if err := enc.EncodeInteger(
						tc.Value,
						size,
					); err != nil {
						t.Fatalf(
							"EncodeInteger() = %v",
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						want,
					)

					got, err := DECODERS[aligned](want).DecodeInteger(size)
					if err != nil {
						t.Fatalf(
							"DecodeInteger() = %v",
							err,
						)
					}

					if got != tc.Value {
						t.Fatalf(
							"decoded %d, want %d",
							got,
							tc.Value,
						)
					}
				},
			)
		}
	}
}

// TestRegression_P3UniversalString guards lib/review.md item P3-3. X.691 clause
// 30.5.3 gives every UniversalString character 32 bits in the UNALIGNED variant
// as well (30.5.2 for ALIGNED), where the encoder sized the field for
// utf8.MaxRune and wrote 21. The expected octets come from pycrate
// (testing/regression.py).
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func TestRegression_P3UniversalString(t *testing.T) {
	var file _P3File

	_Load(
		t,
		VECTOR_REGRESSION,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.Strings {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.Type+"_"+tc.Value,
				func(t *testing.T) {
					var (
						size = _Constraint(
							tc.Lb,
							tc.Ub,
							nil,
						)
						want = _Unhex(
							t,
							_Both(
								tc.Aper,
								tc.Uper,
							)[aligned],
						)

						enc = ENCODERS[aligned]()
					)

					if err := enc.EncodeRestrictedString(
						tc.Value,
						per.STRING_UNIVERSAL,
						size,
					); err != nil {
						t.Fatalf(
							"EncodeRestrictedString() = %v",
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						want,
					)

					got, err := DECODERS[aligned](want).DecodeRestrictedString(
						per.STRING_UNIVERSAL,
						size,
					)
					if err != nil {
						t.Fatalf(
							"DecodeRestrictedString() = %v",
							err,
						)
					}

					if got != tc.Value {
						t.Fatalf(
							"decoded %q, want %q",
							got,
							tc.Value,
						)
					}
				},
			)
		}
	}
}

// TestRegression_P3DecodeOutsideRoot guards lib/review.md item P3-4. A
// non-extensible constrained INTEGER (X.691 clause 13.2.2) and ENUMERATED
// (clause 14.2, 14.3) has no value above its root, so a field that holds one is
// a malformed encoding. The input bits are crafted, not an encoding.
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func TestRegression_P3DecodeOutsideRoot(t *testing.T) {
	cases := []struct {
		name    string
		aligned bool
		data    []byte
		decode  func(dec *per.Decoder) error
	}{
		{
			name:    "integer_0_5_value_6",
			aligned: false,
			data:    []byte{0xC0},
			decode: _DecodeIntegerTo(
				0,
				5,
			),
		},
		{
			name:    "integer_0_5_value_7",
			aligned: true,
			data:    []byte{0xE0},
			decode: _DecodeIntegerTo(
				0,
				5,
			),
		},
		{
			name:    "integer_10_15_offset_7",
			aligned: false,
			data:    []byte{0xE0},
			decode: _DecodeIntegerTo(
				10,
				15,
			),
		},
		{
			name:    "integer_0_200_offset_255",
			aligned: true,
			data:    []byte{0xFF},
			decode: _DecodeIntegerTo(
				0,
				200,
			),
		},
		{
			name:    "integer_0_1000_offset_65535",
			aligned: true,
			data:    []byte{0xFF, 0xFF},
			decode: _DecodeIntegerTo(
				0,
				1000,
			),
		},
		{
			name:    "integer_0_70000_aper_offset_16777215",
			aligned: true,
			data:    []byte{0x80, 0xFF, 0xFF, 0xFF},
			decode: _DecodeIntegerTo(
				0,
				70000,
			),
		},
		{
			name:    "integer_0_70000_uper_offset_131071",
			aligned: false,
			data:    []byte{0xFF, 0xFF, 0x80},
			decode: _DecodeIntegerTo(
				0,
				70000,
			),
		},
		{
			name:    "enumerated_3_items_index_3_uper",
			aligned: false,
			data:    []byte{0xC0},
			decode:  _DecodeEnumeratedTo(2),
		},
		{
			name:    "enumerated_3_items_index_3_aper",
			aligned: true,
			data:    []byte{0xC0},
			decode:  _DecodeEnumeratedTo(2),
		},
		{
			name:    "enumerated_5_items_index_7",
			aligned: false,
			data:    []byte{0xE0},
			decode:  _DecodeEnumeratedTo(4),
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				err := tc.decode(DECODERS[tc.aligned](tc.data))
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

// TestRegression_P3EmptyEncoding guards lib/review.md item P3-5. X.691 clauses
// 11.1.3.1 and 11.1.4 make the outermost empty bit string one octet 0x00, in
// both variants, and the decoder takes that octet back. The encoder returned no
// octets. The expected octets come from pycrate (testing/regression.py).
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func TestRegression_P3EmptyEncoding(t *testing.T) {
	var file _P3File

	_Load(
		t,
		VECTOR_REGRESSION,
		&file,
	)

	cases := []struct {
		name   string
		encode func(enc *per.Encoder) error
		decode func(dec *per.Decoder) error
	}{
		{
			name: "nothing_written",
			encode: func(enc *per.Encoder) error {
				return nil
			},
			decode: func(dec *per.Decoder) error {
				return nil
			},
		},
		{
			name: "Null",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeNull()
			},
			decode: func(dec *per.Decoder) error {
				return dec.DecodeNull()
			},
		},
		{
			name: "Single",
			encode: func(enc *per.Encoder) error {
				return enc.EncodeInteger(
					5,
					per.Constrained(
						5,
						5,
					),
				)
			},
			decode: func(dec *per.Decoder) error {
				got, err := dec.DecodeInteger(per.Constrained(
					5,
					5,
				))
				if err != nil {
					return err
				}

				if got != 5 {
					return per.ErrValueOutOfRange
				}

				return nil
			},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					enc := ENCODERS[aligned]()

					if err := tc.encode(enc); err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						[]byte{0x00},
					)

					err := tc.decode(DECODERS[aligned]([]byte{0x00}))
					if err != nil {
						t.Fatalf(
							"decode of 00 = %v",
							err,
						)
					}
				},
			)
		}
	}

	// The oracle agrees: pycrate writes 00 for both types and both variants.
	for _, row := range file.Empty {
		if row.Aper != "00" || row.Uper != "00" {
			t.Fatalf(
				"oracle %s: aper %s uper %s, want 00 and 00",
				row.Type,
				row.Aper,
				row.Uper,
			)
		}
	}
}

// _DecodeIntegerTo returns a decode step for INTEGER (lb..ub).
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func _DecodeIntegerTo(
	lb,
	ub int64,
) func(dec *per.Decoder) error {
	return func(dec *per.Decoder) error {
		_, err := dec.DecodeInteger(per.Constrained(
			lb,
			ub,
		))

		return err
	}
}

// _DecodeEnumeratedTo returns a decode step for an ENUMERATED whose root has
// indices 0 to upper.
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func _DecodeEnumeratedTo(upper int64) func(dec *per.Decoder) error {
	return func(dec *per.Decoder) error {
		_, err := dec.DecodeEnumerated(per.Constrained(
			0,
			upper,
		))

		return err
	}
}

// _Both pairs the text of the ALIGNED variant with that of the UNALIGNED one.
//
// Revisions:
//   - 2026-10-19 11:09: initial creation
func _Both(
	aper,
	uper string,
) map[bool]string {
	return map[bool]string{
		true:  aper,
		false: uper,
	}
}

// TestRegression_P3FragmentedWithinBound is the guard of the 70001-octet case in
// TestRegression_P3SizeOutOfRangeDecode: the same input is valid under
// SIZE(0..80000) (X.691 clauses 11.9.3.8 and 17.8).
//
// Revisions:
//   - 2026-10-19 11:16: initial creation
func TestRegression_P3FragmentedWithinBound(t *testing.T) {
	got, err := per.NewAlignedDecoder(_Fragmented70001()).DecodeOctetString(per.Constrained(
		0,
		80000,
	))
	if err != nil {
		t.Fatalf(
			"DecodeOctetString() = %v",
			err,
		)
	}

	if len(got) != 70001 {
		t.Fatalf(
			"decoded %d octets, want 70001",
			len(got),
		)
	}
}

// _Fragmented70001 builds 70001 octets of 0xFF in the fragmented form: 0xC4,
// 65536 octets, 0x91 0x71, 4465 octets.
//
// Revisions:
//   - 2026-10-19 11:16: initial creation
func _Fragmented70001() []byte {
	data := []byte{0xC4}
	data = append(
		data,
		bytes.Repeat(
			[]byte{0xFF},
			65536,
		)...,
	)
	data = append(
		data,
		0x91,
		0x71,
	)

	return append(
		data,
		bytes.Repeat(
			[]byte{0xFF},
			4465,
		)...,
	)
}
