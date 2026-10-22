package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _P8Pair is one of the two types that share the SEQUENCE of X.680 36.5 and 44.5: EMBEDDED PDV
// (data-value) and CHARACTER STRING (string-value). write encodes the value; read decodes it and
// returns the identification and the octets.
type _P8Pair struct {
	name  string
	kind  string
	write func(
		enc *per.Encoder,
		ident *per.Identification,
		data []byte,
	) error
	read func(dec *per.Decoder) (*per.Identification, []byte, error)
}

// _P8Pairs lists the two types.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Pairs() []*_P8Pair {
	return []*_P8Pair{
		{
			name: "EmbeddedPDV",
			kind: P8_PDV,
			write: func(
				enc *per.Encoder,
				ident *per.Identification,
				data []byte,
			) error {
				return enc.EncodeEmbeddedPDV(&per.EmbeddedPDV{
					Identification: ident,
					DataValue:      data,
				})
			},
			read: func(dec *per.Decoder) (*per.Identification, []byte, error) {
				value, err := dec.DecodeEmbeddedPDV()
				if err != nil {
					return nil, nil, err
				}

				return value.Identification, value.DataValue, nil
			},
		},
		{
			name: "CharacterString",
			kind: P8_CS,
			write: func(
				enc *per.Encoder,
				ident *per.Identification,
				data []byte,
			) error {
				return enc.EncodeCharacterString(&per.CharacterString{
					Identification: ident,
					StringValue:    data,
				})
			},
			read: func(dec *per.Decoder) (*per.Identification, []byte, error) {
				value, err := dec.DecodeCharacterString()
				if err != nil {
					return nil, nil, err
				}

				return value.Identification, value.StringValue, nil
			},
		},
	}
}

// _Rows returns the rows of a pair.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func (p *_P8Pair) _Rows(file *_P8File) []*_P8Row {
	if p.kind == P8_PDV {
		return file.Pdv
	}

	return file.Cs
}

// TestPairs_Vectors checks EncodeEmbeddedPDV and EncodeCharacterString against the octets of
// the oracles (testing/pdvs.py), and the decoders against the same octets. The general case
// is the SEQUENCE of X.680 36.5 and 44.5 without data-value-descriptor and without a preamble
// (X.691 28.3, 31.3): the CHOICE index in 3 bits (six alternatives, no extension marker, X.691
// 23.6), the alternative, then the data value as an OCTET STRING (X.691 17.8: unconstrained,
// length determinant and octets, aligned in ALIGNED). Every identification alternative is
// there, with data values of 0, 3, 127, 128, 300 and 16384 octets (11.9.3.3, 11.9.3.5, 11.9.3.8).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestPairs_Vectors(t *testing.T) {
	file := _P8Load(t)

	for _, pair := range _P8Pairs() {
		for _, aligned := range []bool{true, false} {
			for index, row := range pair._Rows(file) {
				t.Run(
					pair.name+"_"+VARIANT_NAMES[aligned]+"_"+_P8Name(
						row,
						index,
					),
					func(t *testing.T) {
						var (
							ident = _P8Identification(
								t,
								row.Identification,
							)
							data = _P8Octets(
								t,
								row.Data,
							)
							enc = ENCODERS[aligned]()
						)

						if err := pair.write(
							enc,
							ident,
							data,
						); err != nil {
							t.Fatalf(
								"encode = %v",
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

							gotIdent, gotData, err = pair.read(dec)
						)
						if err != nil {
							t.Fatalf(
								"decode = %v",
								err,
							)
						}

						_P8SameIdentification(
							t,
							gotIdent,
							ident,
						)
						_P8SameOctets(
							t,
							gotData,
							data,
						)
					},
				)
			}
		}
	}
}

// TestPairs_Framed writes each value between BOOLEAN fields and reads it back. The decoder
// must stop at the last bit of the value and keep the padding of the length determinant and of
// the identification (X.691 11.9.3.6, 11.5, 10.9).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestPairs_Framed(t *testing.T) {
	file := _P8Load(t)

	for _, pair := range _P8Pairs() {
		for _, aligned := range []bool{true, false} {
			for index, row := range _P8Rows(pair._Rows(file)) {
				t.Run(
					pair.name+"_"+VARIANT_NAMES[aligned]+"_"+_P8Name(
						row,
						index,
					),
					func(t *testing.T) {
						var (
							ident = _P8Identification(
								t,
								row.Identification,
							)
							data = _P8Octets(
								t,
								row.Data,
							)
						)

						_CheckFramed(
							t,
							aligned,
							func(enc *per.Encoder) error {
								return pair.write(
									enc,
									ident,
									data,
								)
							},
							func(dec *per.Decoder) error {
								got, octets, err := pair.read(dec)
								if err != nil {
									return err
								}

								_P8SameIdentification(
									t,
									got,
									ident,
								)
								_P8SameOctets(
									t,
									octets,
									data,
								)

								return nil
							},
						)
					},
				)
			}
		}
	}
}

// TestPredefined_Vectors checks the predefined case of EMBEDDED PDV and CHARACTER STRING:
// with identification constrained to fixed (or syntaxes to one value) only the data value is
// sent, and it is the PER encoding of an OCTET STRING of the octets of the complete encoding
// (X.691 28.2, 31.2). The codec of that case is Encoder.EncodeOctetString with an
// unconstrained size; the vectors are the OCTET STRING answers of the oracles (type
// Predefined), and the identification is not in them.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestPredefined_Vectors(t *testing.T) {
	file := _P8Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.Predefined {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P8Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						data = _P8Octets(
							t,
							row.Data,
						)
						enc = ENCODERS[aligned]()
					)

					if err := enc.EncodeOctetString(
						data,
						per.Unconstrained(),
					); err != nil {
						t.Fatalf(
							"EncodeOctetString = %v",
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

						got, err = dec.DecodeOctetString(
							per.Unconstrained(),
						)
					)
					if err != nil {
						t.Fatalf(
							"DecodeOctetString = %v",
							err,
						)
					}

					_P8SameOctets(
						t,
						got,
						data,
					)
				},
			)
		}
	}
}

// TestPredefined_GeneralIsNotPredefined checks that the general codec does not take the
// predefined shortcut by itself: a value whose identification is the alternative fixed is
// still written with its identification (X.691 28.1 b) and 31.1 b): the shortcut needs an inner
// type constraint, which a codec without a constraint does not have). The octets are the
// oracle answers for the general SEQUENCE and are longer than the OCTET STRING of the data.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestPredefined_GeneralIsNotPredefined(t *testing.T) {
	file := _P8Load(t)

	for _, pair := range _P8Pairs() {
		for _, aligned := range []bool{true, false} {
			t.Run(
				pair.name+"_"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					var row *_P8Row

					for _, candidate := range _P8Rows(pair._Rows(file)) {
						if _P8IsFixedWithData(candidate) {
							row = candidate
						}
					}

					if row == nil {
						t.Fatalf("no row with the identification fixed")
					}

					var (
						data = _P8Octets(
							t,
							row.Data,
						)
						short = ENCODERS[aligned]()
					)

					if err := short.EncodeOctetString(
						data,
						per.Unconstrained(),
					); err != nil {
						t.Fatalf(
							"EncodeOctetString = %v",
							err,
						)
					}

					enc := ENCODERS[aligned]()

					if err := pair.write(
						enc,
						_P8Identification(
							t,
							row.Identification,
						),
						data,
					); err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					_P8Check(
						t,
						row,
						aligned,
						enc.Bytes(),
					)

					if len(enc.Bytes()) <= len(short.Bytes()) {
						t.Fatalf(
							"general % x, predefined % x",
							enc.Bytes(),
							short.Bytes(),
						)
					}
				},
			)
		}
	}
}

// TestIdentification_Kinds checks that the kind of each alternative is its CHOICE index
// (X.691 23.2: the order of X.680 36.5) and that the six wrappers carry their own kind.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestIdentification_Kinds(t *testing.T) {
	file := _P8Load(t)

	var want = map[string]per.IdentificationKind{
		P8_SYNTAXES:                per.IDENTIFICATION_KIND_SYNTAXES,
		P8_SYNTAX:                  per.IDENTIFICATION_KIND_SYNTAX,
		P8_PRESENTATION_CONTEXT_ID: per.IDENTIFICATION_KIND_PRESENTATION_CONTEXT_ID,
		P8_CONTEXT_NEGOTIATION:     per.IDENTIFICATION_KIND_CONTEXT_NEGOTIATION,
		P8_TRANSFER_SYNTAX:         per.IDENTIFICATION_KIND_TRANSFER_SYNTAX,
		P8_FIXED:                   per.IDENTIFICATION_KIND_FIXED,
	}

	var index = map[string]int64{
		P8_SYNTAXES:                0,
		P8_SYNTAX:                  1,
		P8_PRESENTATION_CONTEXT_ID: 2,
		P8_CONTEXT_NEGOTIATION:     3,
		P8_TRANSFER_SYNTAX:         4,
		P8_FIXED:                   5,
	}

	seen := map[string]bool{}

	for _, row := range file.Pdv {
		alt := row.Identification.Alt
		if seen[alt] {
			continue
		}

		seen[alt] = true

		t.Run(
			alt,
			func(t *testing.T) {
				got := _P8Identification(
					t,
					row.Identification,
				).Choices.Kind()

				if got != want[alt] || int64(got) != index[alt] {
					t.Fatalf(
						"kind of %s = %d, want %d",
						alt,
						got,
						index[alt],
					)
				}
			},
		)
	}

	if len(seen) != len(want) {
		t.Fatalf(
			"rows cover %d alternatives, want %d",
			len(seen),
			len(want),
		)
	}
}

// _P8IsFixedWithData selects a row whose identification is fixed and whose data is a short,
// non-empty hex text.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8IsFixedWithData(row *_P8Row) bool {
	return row.Identification.Alt == P8_FIXED && row.Data.Hex != nil && *row.Data.Hex != ""
}

// _P8IsFixedEmpty selects a row whose identification is fixed and whose data is empty.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8IsFixedEmpty(row *_P8Row) bool {
	return row.Identification.Alt == P8_FIXED && row.Data.Hex != nil && *row.Data.Hex == ""
}

// _P8IsEmptySyntax selects the EXTERNAL row of the syntax of 8 arcs with no descriptor and an
// empty octet-aligned value.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8IsEmptySyntax(row *_P8Row) bool {
	empty := row.Encoding.Data != nil && row.Encoding.Data.Hex != nil &&
		*row.Encoding.Data.Hex == ""

	return row.Identification.Alt == P8_SYNTAX && row.Descriptor == nil &&
		row.Encoding.Alt == P8_OCTET_ALIGNED && empty && len(row.Identification.OID) == 8
}
