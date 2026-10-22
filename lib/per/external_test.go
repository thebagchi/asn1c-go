package per_test

import (
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// P8_TABLE_1 is Table 1 of X.691 29.4: for each identification that EXTERNAL can hold, which of
// direct-reference and indirect-reference are present. The three other alternatives CANNOT
// OCCUR and are not in the table.
var (
	P8_TABLE_1 = map[string][2]bool{
		P8_SYNTAX:                  {true, false},
		P8_PRESENTATION_CONTEXT_ID: {false, true},
		P8_CONTEXT_NEGOTIATION:     {true, true},
	}
)

// P8_BY_PRESENCE maps the presence of (direct-reference, indirect-reference) to the alternative
// of identification that a decoder returns, the inverse of Table 1.
var (
	P8_BY_PRESENCE = map[[2]bool]per.IdentificationKind{
		{true, false}: per.IDENTIFICATION_KIND_SYNTAX,
		{false, true}: per.IDENTIFICATION_KIND_PRESENTATION_CONTEXT_ID,
		{true, true}:  per.IDENTIFICATION_KIND_CONTEXT_NEGOTIATION,
	}
)

// TestExternal_Vectors checks EncodeExternal against the octets of the oracles for the SEQUENCE
// of X.691 29.1 (type ExtSeq of testing/pdvs.py), and DecodeExternal against the same octets.
// The preamble is three bits (direct-reference, indirect-reference, data-value-descriptor, all
// OPTIONAL, no extension marker, 19.2), then the references and the descriptor, each unconstrained
// (an OBJECT IDENTIFIER, an INTEGER, a GraphicString of 30.6), then the encoding CHOICE in 2
// bits (23.6). The identification maps by Table 1 (29.4): syntax is direct only,
// presentation-context-id indirect only, context-negotiation both. single-ASN1-type is an open
// type (29.9, 11.2.2); octet-aligned an OCTET STRING; arbitrary a BIT STRING (16.11).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestExternal_Vectors(t *testing.T) {
	file := _P8Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.Ext {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						value = _P8External(
							t,
							row,
						)
						enc = ENCODERS[aligned]()
					)

					if err := enc.EncodeExternal(value); err != nil {
						t.Fatalf(
							"EncodeExternal = %v",
							err,
						)
					}

					_P8Check(
						t,
						row,
						aligned,
						enc.Bytes(),
					)

					got, err := DECODERS[aligned](enc.Bytes()).DecodeExternal()
					if err != nil {
						t.Fatalf(
							"DecodeExternal = %v",
							err,
						)
					}

					_P8SameExternal(
						t,
						got,
						value,
					)
				},
			)
		}
	}
}

// TestExternal_Framed writes each value between BOOLEAN fields and reads it back, so that a
// decoder that stops early or late, or skips the wrong padding after the preamble, the
// references, the descriptor or the open type, reads a wrong BOOLEAN.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestExternal_Framed(t *testing.T) {
	file := _P8Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P8Rows(file.Ext) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					value := _P8External(
						t,
						row,
					)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeExternal(value)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeExternal()
							if err != nil {
								return err
							}

							_P8SameExternal(
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

// TestExternal_Table1 checks the mapping of Table 1 of X.691 29.4 on the decode side: the
// identification that DecodeExternal returns is the one that the references present in the
// octets select: direct only gives syntax, indirect only presentation-context-id, both
// context-negotiation. The octets are oracle answers for references that P8_TABLE_1 lists for
// the row; the expected kind comes from the presence pair, not from the alternative of the row.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestExternal_Table1(t *testing.T) {
	var (
		file = _P8Load(t)
		seen = map[string]bool{}
	)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P8Rows(file.Ext) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					_, known := P8_TABLE_1[row.Identification.Alt]
					if !known {
						t.Fatalf(
							"%q is not in Table 1",
							row.Identification.Alt,
						)
					}

					seen[row.Identification.Alt] = true

					var (
						table = P8_TABLE_1[row.Identification.Alt]

						want = P8_BY_PRESENCE[table]

						octets = _Unhex(
							t,
							_Both(
								row.Aper,
								row.Uper,
							)[aligned],
						)

						dec = DECODERS[aligned](octets)

						got, err = dec.DecodeExternal()
					)
					if err != nil {
						t.Fatalf(
							"DecodeExternal = %v",
							err,
						)
					}

					if !_P8HasKind(
						got.Identification,
						want,
					) {
						t.Fatalf(
							"identification %+v, want kind %d",
							got.Identification,
							want,
						)
					}
				},
			)
		}
	}

	if len(seen) != len(P8_TABLE_1) {
		t.Fatalf(
			"rows cover %d of the %d alternatives of Table 1",
			len(seen),
			len(P8_TABLE_1),
		)
	}
}

// TestExternal_NoReference decodes the octets of the SEQUENCE of X.691 29.1 with neither
// direct-reference nor indirect-reference (testing/pdvs.py, section neither). Table 1 gives
// every identification at least one reference, so no value of EXTERNAL has these octets, and
// DecodeExternal must refuse them with ErrExternalIdentification and not guess one.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestExternal_NoReference(t *testing.T) {
	file := _P8Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.Neither {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						octets = _Unhex(
							t,
							_Both(
								row.Aper,
								row.Uper,
							)[aligned],
						)

						dec = DECODERS[aligned](octets)

						got, err = dec.DecodeExternal()
					)
					if !errors.Is(
						err,
						per.ErrExternalIdentification,
					) {
						t.Fatalf(
							"DecodeExternal = %+v, %v",
							got,
							err,
						)
					}
				},
			)
		}
	}
}

// TestExternal_EncodingKinds checks that the kind of each alternative of the encoding is its
// CHOICE index (X.691 29.1: single-ASN1-type 0, octet-aligned 1, arbitrary 2).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestExternal_EncodingKinds(t *testing.T) {
	var (
		single    = per.ExternalEncoding_SingleASN1Type{}
		aligned   = per.ExternalEncoding_OctetAligned{}
		arbitrary = per.ExternalEncoding_Arbitrary{}
	)

	for index, choice := range []struct {
		name string
		kind per.ExternalEncodingKind
	}{
		{
			name: P8_SINGLE_ASN1_TYPE,
			kind: single.Kind(),
		},
		{
			name: P8_OCTET_ALIGNED,
			kind: aligned.Kind(),
		},
		{
			name: P8_ARBITRARY,
			kind: arbitrary.Kind(),
		},
	} {
		if int64(choice.kind) != int64(index) {
			t.Fatalf(
				"kind of %s = %d, want %d",
				choice.name,
				choice.kind,
				index,
			)
		}
	}
}

// _P8HasKind reports whether an identification holds an alternative of the given kind.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8HasKind(
	ident *per.Identification,
	kind per.IdentificationKind,
) bool {
	return ident != nil && ident.Choices != nil && ident.Choices.Kind() == kind
}
