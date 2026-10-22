package per_test

import (
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

const (
	KIND_IRI          = "iri"
	KIND_RELATIVE_IRI = "relative_iri"
)

type _P4IRI struct {
	_P4Oracles
	Type  string `json:"type"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type _P4IRIFile struct {
	IRI []*_P4IRI `json:"iri"`
}

// _IRICodec pairs the encoder and the decoder of one of the two IRI types.
type _IRICodec struct {
	encode func(
		enc *per.Encoder,
		value string,
	) error
	decode func(dec *per.Decoder) (string, error)
}

// IRI_CODECS holds the codec of each kind of row in testing.json (iri).
var (
	IRI_CODECS = map[string]*_IRICodec{
		KIND_IRI: {
			encode: (*per.Encoder).EncodeIRI,
			decode: (*per.Decoder).DecodeIRI,
		},
		KIND_RELATIVE_IRI: {
			encode: (*per.Encoder).EncodeRelativeIRI,
			decode: (*per.Decoder).DecodeRelativeIRI,
		},
	}
)

// TestIRI_Vectors checks EncodeIRI and EncodeRelativeIRI against the octets of
// pycrate and OTP (testing/iri.py), and the decoders against the same octets.
// No oracle compiles OID-IRI or RELATIVE-OID-IRI. X.691 clauses 26 and 27
// take the contents octets of BER, which are the UTF-8 octets of the value text
// (X.690 clauses 8.21 and 8.22), behind a length determinant counted in octets
// (11.9). That is the encoding of an unconstrained UTF8String (30.5), so both
// oracles were asked for a UTF8String of the same text. The values include
// non-ASCII labels, and lengths on both sides of 16K (11.9.3.8: fragments).
// The tests do not check the IRI syntax of X.680 clauses 34 and 35: X.691 asks
// only for the contents octets, so a text is carried as it is.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
//   - 2026-10-20 00:45: check a long answer by its sha256 and length
func TestIRI_Vectors(t *testing.T) {
	var file _P4IRIFile

	_Load(
		t,
		VECTOR_IRI,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.IRI {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.Kind+"_"+_IRIName(tc.Value),
				func(t *testing.T) {
					var (
						codec = IRI_CODECS[tc.Kind]

						enc = ENCODERS[aligned]()
					)
					if err := codec.encode(
						enc,
						tc.Value,
					); err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							enc.Bytes(),
						)

						got, err = codec.decode(DECODERS[aligned](want))
					)
					if err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					if got != tc.Value {
						t.Fatalf(
							"decode = %q, want %q",
							_IRIName(got),
							_IRIName(tc.Value),
						)
					}
				},
			)
		}
	}
}

// TestIRI_Framed writes each vector text between BOOLEAN fields and reads it
// back (X.691 clauses 26, 27 and 11.9). The decoder must stop at the last bit
// of the text, also after a fragmented length.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
func TestIRI_Framed(t *testing.T) {
	var file _P4IRIFile

	_Load(
		t,
		VECTOR_IRI,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.IRI {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.Kind+"_"+_IRIName(tc.Value),
				func(t *testing.T) {
					codec := IRI_CODECS[tc.Kind]

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return codec.encode(
								enc,
								tc.Value,
							)
						},
						func(dec *per.Decoder) error {
							got, err := codec.decode(dec)
							if err == nil && got != tc.Value {
								t.Errorf(
									"decode = %q, want %q",
									_IRIName(got),
									_IRIName(tc.Value),
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

// TestIRI_InvalidUTF8 checks the one refusal the tests ask of the IRI codecs. The
// contents octets of an IRI are UTF-8 (X.690 clauses 8.21 and 8.22, used by
// X.691 clauses 26 and 27), so a text with an octet sequence that is not UTF-8
// has no encoding, and input with such octets is not an encoding. The clauses
// do not ask PER to check the label syntax of X.680 clauses 34.3 and 35.3, so
// the tests do not either. The control case is valid.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
func TestIRI_InvalidUTF8(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
		valid bool
	}{
		{
			name:  "control_valid",
			bytes: []byte("/ISO/Ä"),
			valid: true,
		},
		{
			name:  "lone_continuation",
			bytes: []byte{'/', 'a', 0x80},
		},
		{
			name:  "invalid_lead",
			bytes: []byte{'/', 0xFF, 0xFE},
		},
		{
			name:  "truncated_sequence",
			bytes: []byte{'/', 'a', 0xE6, 0x97},
		},
		{
			name:  "overlong_slash",
			bytes: []byte{'/', 0xC0, 0xAF},
		},
		{
			name:  "surrogate",
			bytes: []byte{'/', 0xED, 0xA0, 0x80},
		},
	}

	for kind, codec := range IRI_CODECS {
		for _, aligned := range []bool{true, false} {
			for _, tc := range cases {
				t.Run(
					kind+"_"+VARIANT_NAMES[aligned]+"_"+tc.name,
					func(t *testing.T) {
						var (
							encErr = codec.encode(
								ENCODERS[aligned](),
								string(tc.bytes),
							)

							data = append(
								[]byte{byte(len(tc.bytes))},
								tc.bytes...,
							)
							_, decErr = codec.decode(
								DECODERS[aligned](data),
							)
						)

						if tc.valid {
							if encErr != nil || decErr != nil {
								t.Fatalf(
									"encode = %v, decode = %v",
									encErr,
									decErr,
								)
							}

							return
						}

						if encErr == nil {
							t.Errorf("encode = nil, want error")
						}

						if decErr == nil {
							t.Errorf("decode = nil, want error")
						}
					},
				)
			}
		}
	}
}

// _IRIName shortens a text for a subtest name or a message.
//
// Revisions:
//   - 2026-10-19 11:33: initial creation
func _IRIName(text string) string {
	const LIMIT = 40

	runes := []rune(text)
	if len(runes) <= LIMIT {
		return text
	}

	return fmt.Sprintf(
		"%s...%d",
		string(runes[:LIMIT]),
		len(runes),
	)
}
