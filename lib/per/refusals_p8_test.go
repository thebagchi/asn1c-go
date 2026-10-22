package per_test

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// P8_INDEX_ABOVE_ROOT are the CHOICE indices of the 3-bit field of the identification that no
// alternative has. X.680 36.5 has no extension marker, so the decoder cannot treat them as
// additions (X.691 23.6): they are errors.
var (
	P8_INDEX_ABOVE_ROOT = []byte{
		6,
		7,
	}
)

// _P8Encoder is one type that carries an identification. write runs its encoder on the
// identification that a refusal case gives and on valid data.
type _P8Encoder struct {
	name  string
	write func(
		enc *per.Encoder,
		ident *per.Identification,
	) error
}

// _P8Encoders returns an encoder for each of the three types that carry an identification, in
// the order EMBEDDED PDV, CHARACTER STRING, EXTERNAL, each with valid data around the
// identification under test.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Encoders() []*_P8Encoder {
	octets := per.ExternalEncoding_OctetAligned{
		1,
		2,
		3,
	}

	return []*_P8Encoder{
		{
			name: "EmbeddedPDV",
			write: func(
				enc *per.Encoder,
				ident *per.Identification,
			) error {
				return enc.EncodeEmbeddedPDV(&per.EmbeddedPDV{
					Identification: ident,
					DataValue:      octets,
				})
			},
		},
		{
			name: "CharacterString",
			write: func(
				enc *per.Encoder,
				ident *per.Identification,
			) error {
				return enc.EncodeCharacterString(&per.CharacterString{
					Identification: ident,
					StringValue:    octets,
				})
			},
		},
		{
			name: "External",
			write: func(
				enc *per.Encoder,
				ident *per.Identification,
			) error {
				return enc.EncodeExternal(&per.External{
					Identification: ident,
					Encoding: &per.ExternalEncoding{
						Choices: &octets,
					},
				})
			},
		},
	}
}

// _P8Syntax makes the identification syntax of one object identifier.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Syntax(arcs ...int) *per.Identification {
	syntax := per.Identification_Syntax(arcs)

	return &per.Identification{
		Choices: &syntax,
	}
}

// _P8NoWrite checks that a refused encode left the encoder as it was: a BOOLEAN written after
// the refusal is the only content. The checks come before the first write (validate, then write),
// which the previous phase does the same way.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8NoWrite(
	t *testing.T,
	enc *per.Encoder,
) {
	t.Helper()

	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatalf(
			"EncodeBoolean = %v",
			err,
		)
	}

	_Compare(
		t,
		enc.Bytes(),
		[]byte{0x80},
	)
}

// TestRefusals_NilIdentification checks that the types that need an identification refuse a
// nil one, and one with no alternative, with ErrNilValue; the control, a valid syntax, encodes.
// The encoder holds nothing after the refusal.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_NilIdentification(t *testing.T) {
	cases := []struct {
		name  string
		ident *per.Identification
		valid bool
	}{
		{
			name:  "nil",
			ident: nil,
		},
		{
			name:  "no_alternative",
			ident: &per.Identification{},
		},
		{
			name: "control",
			ident: _P8Syntax(
				1,
				3,
				6,
			),
			valid: true,
		},
	}

	for _, encoder := range _P8Encoders() {
		for _, aligned := range []bool{true, false} {
			for _, tc := range cases {
				t.Run(
					encoder.name+"_"+VARIANT_NAMES[aligned]+"_"+tc.name,
					func(t *testing.T) {
						var (
							enc = ENCODERS[aligned]()
							err = encoder.write(
								enc,
								tc.ident,
							)
						)

						if tc.valid {
							if err != nil {
								t.Fatalf(
									"control = %v",
									err,
								)
							}

							return
						}

						if !errors.Is(
							err,
							per.ErrNilValue,
						) {
							t.Fatalf(
								"error = %v, want ErrNilValue",
								err,
							)
						}

						_P8NoWrite(
							t,
							enc,
						)
					},
				)
			}
		}
	}
}

// TestRefusals_NilValue checks that each encoder refuses a nil value with ErrNilValue, and that
// an EXTERNAL with no encoding, or an encoding with no alternative, is refused the same way.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_NilValue(t *testing.T) {
	var (
		ident = _P8Syntax(
			1,
			3,
			6,
		)
		cases = []struct {
			name  string
			write func(enc *per.Encoder) error
		}{
			{
				name: "EmbeddedPDV",
				write: func(enc *per.Encoder) error {
					return enc.EncodeEmbeddedPDV(nil)
				},
			},
			{
				name: "CharacterString",
				write: func(enc *per.Encoder) error {
					return enc.EncodeCharacterString(nil)
				},
			},
			{
				name: "External",
				write: func(enc *per.Encoder) error {
					return enc.EncodeExternal(nil)
				},
			},
			{
				name: "InstanceOf",
				write: func(enc *per.Encoder) error {
					return enc.EncodeInstanceOf(nil)
				},
			},
			{
				name: "External_no_encoding",
				write: func(enc *per.Encoder) error {
					return enc.EncodeExternal(&per.External{
						Identification: ident,
					})
				},
			},
			{
				name: "External_no_alternative",
				write: func(enc *per.Encoder) error {
					return enc.EncodeExternal(&per.External{
						Identification: ident,
						Encoding:       &per.ExternalEncoding{},
					})
				},
			},
		}
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					var (
						enc = ENCODERS[aligned]()
						err = tc.write(enc)
					)

					if !errors.Is(
						err,
						per.ErrNilValue,
					) {
						t.Fatalf(
							"error = %v, want ErrNilValue",
							err,
						)
					}

					_P8NoWrite(
						t,
						enc,
					)
				},
			)
		}
	}
}

// TestRefusals_ExternalIdentification checks Table 1 of X.691 29.4: EXTERNAL has no reference
// for syntaxes, transfer-syntax and fixed (CANNOT OCCUR), so EncodeExternal refuses them with
// ErrExternalIdentification before it writes. The same identifications encode as EMBEDDED PDV
// (the control), and the three that Table 1 maps encode as EXTERNAL.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_ExternalIdentification(t *testing.T) {
	var (
		file    = _P8Load(t)
		refused = map[string]bool{
			P8_SYNTAXES:        true,
			P8_TRANSFER_SYNTAX: true,
			P8_FIXED:           true,
		}
		seen = map[string]bool{}
	)

	for _, row := range file.Pdv {
		alt := row.Identification.Alt

		if seen[alt] {
			continue
		}

		seen[alt] = true

		for _, aligned := range []bool{true, false} {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+alt,
				func(t *testing.T) {
					var (
						ident = _P8Identification(
							t,
							row.Identification,
						)
						enc = ENCODERS[aligned]()
						err = _P8Encoders()[2].write(
							enc,
							ident,
						)
					)

					if !refused[alt] {
						if err != nil {
							t.Fatalf(
								"EncodeExternal(%s) = %v",
								alt,
								err,
							)
						}

						return
					}

					if !errors.Is(
						err,
						per.ErrExternalIdentification,
					) {
						t.Fatalf(
							"EncodeExternal(%s) = %v, want sentinel",
							alt,
							err,
						)
					}

					_P8NoWrite(
						t,
						enc,
					)

					control := ENCODERS[aligned]()
					if err := _P8Encoders()[0].write(
						control,
						ident,
					); err != nil {
						t.Fatalf(
							"EncodeEmbeddedPDV(%s) = %v, want a value",
							alt,
							err,
						)
					}
				},
			)
		}
	}
}

// TestRefusals_ObjectIdentifier checks that an object identifier that X.690 8.19 cannot
// encode (a first arc above 2, a second arc of 40 or more under the first arc 0 or 1, fewer than
// two arcs) is refused with ErrValueOutOfRange wherever it stands: in syntax, in syntaxes, in
// context-negotiation, and as the type-id of INSTANCE OF.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_ObjectIdentifier(t *testing.T) {
	good := asn1.ObjectIdentifier{
		1,
		3,
		6,
	}

	var cases = []struct {
		name  string
		write func(
			enc *per.Encoder,
			bad asn1.ObjectIdentifier,
		) error
	}{
		{
			name: "syntax",
			write: func(
				enc *per.Encoder,
				bad asn1.ObjectIdentifier,
			) error {
				return _P8Encoders()[0].write(
					enc,
					_P8Syntax(bad...),
				)
			},
		},
		{
			name: "syntaxes_abstract",
			write: func(
				enc *per.Encoder,
				bad asn1.ObjectIdentifier,
			) error {
				return enc.EncodeEmbeddedPDV(&per.EmbeddedPDV{
					Identification: &per.Identification{
						Choices: &per.Identification_Syntaxes{
							Abstract: bad,
							Transfer: good,
						},
					},
				})
			},
		},
		{
			name: "syntaxes_transfer",
			write: func(
				enc *per.Encoder,
				bad asn1.ObjectIdentifier,
			) error {
				return enc.EncodeCharacterString(&per.CharacterString{
					Identification: &per.Identification{
						Choices: &per.Identification_Syntaxes{
							Abstract: good,
							Transfer: bad,
						},
					},
				})
			},
		},
		{
			name: "context_negotiation",
			write: func(
				enc *per.Encoder,
				bad asn1.ObjectIdentifier,
			) error {
				return enc.EncodeEmbeddedPDV(&per.EmbeddedPDV{
					Identification: &per.Identification{
						Choices: &per.Identification_ContextNegotiation{
							PresentationContextId: 1,
							TransferSyntax:        bad,
						},
					},
				})
			},
		},
		{
			name: "external_syntax",
			write: func(
				enc *per.Encoder,
				bad asn1.ObjectIdentifier,
			) error {
				return _P8Encoders()[2].write(
					enc,
					_P8Syntax(bad...),
				)
			},
		},
		{
			name: "instance_of",
			write: func(
				enc *per.Encoder,
				bad asn1.ObjectIdentifier,
			) error {
				return enc.EncodeInstanceOf(&per.InstanceOf{
					TypeID: bad,
					Value:  []byte{1},
				})
			},
		},
	}

	bads := map[string]asn1.ObjectIdentifier{
		"first_arc_3": {
			3,
			1,
		},
		"second_arc_40": {
			1,
			40,
		},
		"one_arc": {1},
		"empty":   {},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			for name, bad := range bads {
				t.Run(
					VARIANT_NAMES[aligned]+"_"+tc.name+"_"+name,
					func(t *testing.T) {
						err := tc.write(
							ENCODERS[aligned](),
							bad,
						)

						if !errors.Is(
							err,
							per.ErrValueOutOfRange,
						) {
							t.Fatalf(
								"error = %v, want out of range",
								err,
							)
						}
					},
				)
			}
		}
	}
}

// TestRefusals_ShortBitString checks that an arbitrary BIT STRING that claims more bits than
// its octets hold is refused with ErrShortBitString, as EncodeBitString does.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_ShortBitString(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned],
			func(t *testing.T) {
				var (
					bits = per.ExternalEncoding_Arbitrary(asn1.BitString{
						Bytes: []byte{
							0xFF,
						},
						BitLength: 13,
					})

					err = ENCODERS[aligned]().EncodeExternal(&per.External{
						Identification: _P8Syntax(
							1,
							3,
							6,
						),
						Encoding: &per.ExternalEncoding{
							Choices: &bits,
						},
					})
				)

				if !errors.Is(
					err,
					per.ErrShortBitString,
				) {
					t.Fatalf(
						"error = %v, want ErrShortBitString",
						err,
					)
				}
			},
		)
	}
}

// TestRefusals_IdentificationIndex decodes an index of the identification that no alternative
// has. The identification of X.680 36.5 has no extension marker, so the 3-bit field (X.691
// 23.6) holds 0 to 5, and 6 and 7 are ErrValueOutOfRange. The octets are made by hand: they are
// not the encoding of any value, so no oracle has an answer. The control is index 5 (fixed) with
// an empty data value, the octets of the oracles for that value (A0 00 in both variants).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_IdentificationIndex(t *testing.T) {
	file := _P8Load(t)

	for _, pair := range _P8Pairs() {
		for _, aligned := range []bool{true, false} {
			t.Run(
				pair.name+"_"+VARIANT_NAMES[aligned]+"_control",
				func(t *testing.T) {
					var row *_P8Row

					for _, candidate := range pair._Rows(file) {
						if _P8IsFixedEmpty(candidate) {
							row = candidate
						}
					}

					if row == nil {
						t.Fatalf("no row of fixed with no data")
					}

					var (
						octets = _Unhex(
							t,
							_Both(
								row.Aper,
								row.Uper,
							)[aligned],
						)

						dec = DECODERS[aligned](octets)
					)

					if _, _, err := pair.read(dec); err != nil {
						t.Fatalf(
							"control % x = %v",
							octets,
							err,
						)
					}
				},
			)

			for _, index := range P8_INDEX_ABOVE_ROOT {
				name := fmt.Sprintf(
					"%s_%s_%d",
					pair.name,
					VARIANT_NAMES[aligned],
					index,
				)

				t.Run(
					name,
					func(t *testing.T) {
						var (
							octets = []byte{
								index << 5,
								0,
							}

							_, _, err = pair.read(
								DECODERS[aligned](octets),
							)
						)
						if !errors.Is(
							err,
							per.ErrValueOutOfRange,
						) {
							t.Fatalf(
								"decode % x = %v",
								octets,
								err,
							)
						}
					},
				)
			}
		}
	}
}

// TestRefusals_EncodingIndex decodes an EXTERNAL whose encoding CHOICE has the index 3, which
// no alternative has (X.691 29.1 has no extension marker). The octets are the oracle answer for
// an EXTERNAL with the syntax 1.3.6.1.4.1.99.1 and an empty octet-aligned value, with the two
// bits of the index changed from 01 to 11 (APER only: the bits stand at a known octet).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_EncodingIndex(t *testing.T) {
	file := _P8Load(t)

	var row *_P8Row

	for _, candidate := range file.Ext {
		if _P8IsEmptySyntax(candidate) {
			row = candidate
		}
	}

	if row == nil {
		t.Fatalf("no row of syntax with an empty octet-aligned value")
	}

	octets := _Unhex(
		t,
		row.Aper,
	)

	if _, err := per.NewAlignedDecoder(octets).DecodeExternal(); err != nil {
		t.Fatalf(
			"control % x = %v",
			octets,
			err,
		)
	}

	// The last two octets are the octet holding the 2-bit index (01, then padding) and the
	// length 0 of the empty OCTET STRING.
	changed := append(
		[]byte(nil),
		octets...,
	)
	changed[len(changed)-2] |= 0xC0

	if _, err := per.NewAlignedDecoder(changed).DecodeExternal(); !errors.Is(
		err,
		per.ErrValueOutOfRange,
	) {
		t.Fatalf(
			"decode % x = %v",
			changed,
			err,
		)
	}
}

// TestRefusals_Truncated cuts each valid encoding at every octet (a row of more than P8_SHORT_ROW
// octets at the start, the middle and one octet short) and checks that the decoder reports an
// error and does not panic or return a value. The encoder pads only to an octet boundary, so
// every cut loses at least one bit of the value. A cut that ends a length determinant before
// its octets, or an open type before its contents, must not read past the input.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestRefusals_Truncated(t *testing.T) {
	var (
		file     = _P8Load(t)
		decoders = map[string]func(dec *per.Decoder) error{
			P8_PDV: func(dec *per.Decoder) error {
				_, err := dec.DecodeEmbeddedPDV()

				return err
			},
			P8_CS: func(dec *per.Decoder) error {
				_, err := dec.DecodeCharacterString()

				return err
			},
			P8_EXT: func(dec *per.Decoder) error {
				_, err := dec.DecodeExternal()

				return err
			},
			P8_INST: func(dec *per.Decoder) error {
				_, err := dec.DecodeInstanceOf()

				return err
			},
		}
		sections = map[string][]*_P8Row{
			P8_PDV:  file.Pdv,
			P8_CS:   file.Cs,
			P8_EXT:  file.Ext,
			P8_INST: file.Inst,
		}
	)

	for kind, rows := range sections {
		for _, aligned := range []bool{true, false} {
			for index, row := range _P8Rows(rows) {
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

							whole = DECODERS[aligned](octets)
						)

						if err := decoders[kind](whole); err != nil {
							t.Fatalf(
								"control: all %d octets = %v",
								len(octets),
								err,
							)
						}

						for _, cut := range _P8Cuts(len(octets)) {
							var (
								dec = DECODERS[aligned](
									octets[:cut],
								)

								err = decoders[kind](dec)
							)
							if err == nil {
								t.Fatalf(
									"%d of %d octets decode",
									cut,
									len(octets),
								)
							}
						}
					},
				)
			}
		}
	}
}

// _P8Cuts returns the lengths at which the truncation test cuts an encoding of length octets.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Cuts(length int) []int {
	if length <= P8_SHORT_ROW {
		cuts := make(
			[]int,
			length,
		)
		for index := range cuts {
			cuts[index] = index
		}

		return cuts
	}

	return []int{
		0,
		1,
		2,
		length / 2,
		length - 1,
	}
}
