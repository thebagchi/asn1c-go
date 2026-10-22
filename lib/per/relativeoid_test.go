package per_test

import (
	"math"
	"slices"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestRelativeOID_Vectors checks EncodeRelativeOID against the octets of pycrate
// and OTP (testing/relativeoid.py), and DecodeRelativeOID against the same
// octets. X.691 clause 25 puts the contents octets of BER (X.690 clause 8.20)
// behind a length determinant. Every arc is its own subidentifier, written
// base 128 in the shortest form (8.19.2), with no merge of the first two arcs.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-21 21:51: a row whose arc is above the platform int (a 32-bit platform) checks
//     the refusal of the decoder (review P31)
func TestRelativeOID_Vectors(t *testing.T) {
	var file _P4RelativeOIDFile

	_Load(
		t,
		VECTOR_RELATIVE_OID,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.RelativeOID {
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
							_, err = dec.DecodeRelativeOID()
						)

						_CheckArcRefused(
							t,
							err,
						)

						return
					}

					enc := ENCODERS[aligned]()
					if err := enc.EncodeRelativeOID(arcs); err != nil {
						t.Fatalf(
							"EncodeRelativeOID() = %v",
							err,
						)
					}

					_Compare(
						t,
						enc.Bytes(),
						want,
					)

					got, err := DECODERS[aligned](want).DecodeRelativeOID()
					if err != nil {
						t.Fatalf(
							"DecodeRelativeOID() = %v",
							err,
						)
					}

					if !slices.Equal(
						got,
						arcs,
					) {
						t.Fatalf(
							"decode = %v, want %v",
							got,
							arcs,
						)
					}
				},
			)
		}
	}
}

// TestRelativeOID_Framed writes each vector value between BOOLEAN fields and
// reads it back (X.691 clauses 25 and 11.9). The decoder must stop at the last
// bit of the value.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-21 21:51: a row whose arc is above the platform int (a 32-bit platform) checks
//     the refusal of the decoder (review P31)
func TestRelativeOID_Framed(t *testing.T) {
	var file _P4RelativeOIDFile

	_Load(
		t,
		VECTOR_RELATIVE_OID,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.RelativeOID {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_ArcsName(tc.Value),
				func(t *testing.T) {
					arcs, fits := _PlatformArcs(tc.Value)
					if !fits {
						t.Skip(P4_SKIP_WIDE)
					}

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeRelativeOID(arcs)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeRelativeOID()
							if err == nil && !slices.Equal(
								got,
								arcs,
							) {
								t.Errorf(
									"decode = %v, want %v",
									got,
									arcs,
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

// TestRelativeOID_EncodeRefused checks values that have no encoding. An arc is
// a non-negative number (X.680 clause 33, NumberForm). The empty list is also
// refused: RelativeOIDValue in X.680 clause 33 holds RelativeOIDComponentsList,
// which has one or more components, so no value of the type has zero arcs. Both
// oracles would write the single octet 0x00 for it, a length of zero; this
// decision follows the notation, not the oracles. The control case is valid.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
func TestRelativeOID_EncodeRefused(t *testing.T) {
	cases := []struct {
		name  string
		value []int
		valid bool
	}{
		{
			name:  "control_valid",
			value: []int{5, 6},
			valid: true,
		},
		{
			name:  "nil",
			value: nil,
		},
		{
			name:  "empty",
			value: []int{},
		},
		{
			name:  "negative_only",
			value: []int{-1},
		},
		{
			name:  "negative_first",
			value: []int{-1, 5},
		},
		{
			name:  "negative_last",
			value: []int{5, 6, -7},
		},
		{
			name:  "min_int64",
			value: []int{math.MinInt},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					err := ENCODERS[aligned]().EncodeRelativeOID(tc.value)

					if tc.valid {
						if err != nil {
							t.Fatalf(
								"EncodeRelativeOID() = %v",
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

// TestRelativeOID_DecodeRefused checks contents octets that are not a valid
// encoding. Each input is the length octet and the contents. A subidentifier has
// no leading octet 0x80 (X.690 clause 8.19.2, used by 8.20.2) and its last octet
// has bit 8 clear. A length of zero is refused for the reason in
// TestRelativeOID_EncodeRefused. An arc above math.MaxInt64 does not fit the Go
// int. The control cases are valid.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
func TestRelativeOID_DecodeRefused(t *testing.T) {
	cases := []struct {
		name  string
		data  []byte
		want  []int
		valid bool
	}{
		{
			name:  "control_5_6",
			data:  []byte{0x02, 0x05, 0x06},
			want:  []int{5, 6},
			valid: true,
		},
		{
			name:  "control_8571",
			data:  []byte{0x02, 0xC2, 0x7B},
			want:  []int{8571},
			valid: true,
		},
		{
			name: "no_contents",
			data: []byte{0x00},
		},
		{
			name: "first_arc_padded",
			data: []byte{0x02, 0x80, 0x05},
		},
		{
			name: "later_arc_padded",
			data: []byte{0x04, 0x05, 0x80, 0x80, 0x01},
		},
		{
			name: "last_arc_truncated",
			data: []byte{0x02, 0x05, 0x86},
		},
		{
			name: "only_arc_truncated",
			data: []byte{0x01, 0x86},
		},
		{
			name: "arc_above_int64",
			data: []byte{
				0x0A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
			},
		},
		{
			name: "length_above_input",
			data: []byte{0x05, 0x05},
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
					got, err := DECODERS[aligned](tc.data).DecodeRelativeOID()

					if tc.valid {
						if err != nil {
							t.Fatalf(
								"DecodeRelativeOID() = %v",
								err,
							)
						}

						if !slices.Equal(
							got,
							tc.want,
						) {
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
							"DecodeRelativeOID() = %v, want an error",
							got,
						)
					}
				},
			)
		}
	}
}
