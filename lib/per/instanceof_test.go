package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestInstanceOf_Vectors checks EncodeInstanceOf against the octets of the oracles for the
// associated type of X.681 Annex C.7, SEQUENCE { type-id &id, value [0] &Type } (type InstSeq of
// testing/pdvs.py; OTP also encodes INSTANCE OF OF TYPE-IDENTIFIER itself, with the same
// octets). There is no preamble (no OPTIONAL component, no extension marker). type-id is an
// OBJECT IDENTIFIER (X.691 24: an unconstrained length and the contents); value is
// an open type (X.691 11.2.2): the complete encoding of the &Type value as an unconstrained
// OCTET STRING. The EXPLICIT tag is not in PER. Two type-ids, values of 1, 2, 3, 127, 128, 300
// and 16384 octets.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestInstanceOf_Vectors(t *testing.T) {
	file := _P8Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.Inst {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						value = _P8Instance(
							t,
							row,
						)
						enc = ENCODERS[aligned]()
					)

					if err := enc.EncodeInstanceOf(value); err != nil {
						t.Fatalf(
							"EncodeInstanceOf = %v",
							err,
						)
					}

					_P8Check(
						t,
						row,
						aligned,
						enc.Bytes(),
					)

					var (
						dec = DECODERS[aligned](enc.Bytes())

						got, err = dec.DecodeInstanceOf()
					)
					if err != nil {
						t.Fatalf(
							"DecodeInstanceOf = %v",
							err,
						)
					}

					_P8SameInstance(
						t,
						got,
						value,
					)
				},
			)
		}
	}
}

// TestInstanceOf_Framed writes each value between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestInstanceOf_Framed(t *testing.T) {
	file := _P8Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P8Rows(file.Inst) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					value := _P8Instance(
						t,
						row,
					)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeInstanceOf(value)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeInstanceOf()
							if err != nil {
								return err
							}

							_P8SameInstance(
								t,
								got,
								value,
							)

							return nil
						},
					)
				},
			)
		}
	}
}

// _P8SameInstance reports a decoded INSTANCE OF that differs from the one written.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8SameInstance(
	t *testing.T,
	got,
	want *per.InstanceOf,
) {
	t.Helper()

	if got == nil {
		t.Fatalf("decoded INSTANCE OF is nil")
	}

	if len(got.TypeID) != len(want.TypeID) {
		t.Fatalf(
			"type-id %v, want %v",
			got.TypeID,
			want.TypeID,
		)
	}

	for index := range want.TypeID {
		if got.TypeID[index] != want.TypeID[index] {
			t.Fatalf(
				"type-id %v, want %v",
				got.TypeID,
				want.TypeID,
			)
		}
	}

	_P8SameOctets(
		t,
		got.Value,
		want.Value,
	)
}
