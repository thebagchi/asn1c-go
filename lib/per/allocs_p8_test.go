package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// ALLOC_ENCODE_MAX is what the encoders of phase 8 may allocate beyond the encoder itself: no
// allocation per value (the plan's rule for the codecs). The value is built before the
// measurement, as generated code holds it. The measurement subtracts an encoder that writes only
// the first BOOLEAN.
const (
	ALLOC_ENCODE_MAX = 0
)

// P8_ALLOC_SHORT and P8_ALLOC_LONG are the data sizes of the decode measurement: the count of
// allocations must not grow with the size of the value, because a decoder returns one slice
// for the data and must not allocate for each octet or each fragment.
const (
	P8_ALLOC_SHORT = 3
	P8_ALLOC_LONG  = 300
)

// _P8AllocCase is one type of this phase. value builds a value whose data has the given number of
// octets; write encodes it on an encoder after a BOOLEAN; read decodes from a decoder after the
// BOOLEAN.
type _P8AllocCase struct {
	name  string
	write func(
		enc *per.Encoder,
		size int,
	) func() error
	read func(dec *per.Decoder) error
}

// _P8AllocCases builds the cases. The identification is a context-negotiation (the largest
// of the three that EXTERNAL holds: an INTEGER and an OBJECT IDENTIFIER).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8AllocCases() []*_P8AllocCase {
	ident := func() *per.Identification {
		return &per.Identification{
			Choices: &per.Identification_ContextNegotiation{
				PresentationContextId: 5,
				TransferSyntax: []int{
					0,
					0,
					13,
					35,
					3,
					2,
				},
			},
		}
	}

	return []*_P8AllocCase{
		{
			name: "EmbeddedPDV",
			write: func(
				enc *per.Encoder,
				size int,
			) func() error {
				value := &per.EmbeddedPDV{
					Identification: ident(),
					DataValue:      _FragmentOctets(size),
				}

				return func() error {
					return enc.EncodeEmbeddedPDV(value)
				}
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeEmbeddedPDV()

				return err
			},
		},
		{
			name: "CharacterString",
			write: func(
				enc *per.Encoder,
				size int,
			) func() error {
				value := &per.CharacterString{
					Identification: ident(),
					StringValue:    _FragmentOctets(size),
				}

				return func() error {
					return enc.EncodeCharacterString(value)
				}
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeCharacterString()

				return err
			},
		},
		{
			name: "External_octet_aligned",
			write: func(
				enc *per.Encoder,
				size int,
			) func() error {
				var (
					octets = per.ExternalEncoding_OctetAligned(
						_FragmentOctets(size),
					)
					descriptor = "Test PDU"
					value      = &per.External{
						Identification:      ident(),
						DataValueDescriptor: &descriptor,
						Encoding: &per.ExternalEncoding{
							Choices: &octets,
						},
					}
				)

				return func() error {
					return enc.EncodeExternal(value)
				}
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeExternal()

				return err
			},
		},
		{
			name: "External_single_ASN1_type",
			write: func(
				enc *per.Encoder,
				size int,
			) func() error {
				var (
					inner = per.ExternalEncoding_SingleASN1Type(
						_FragmentOctets(size),
					)
					value = &per.External{
						Identification: ident(),
						Encoding: &per.ExternalEncoding{
							Choices: &inner,
						},
					}
				)

				return func() error {
					return enc.EncodeExternal(value)
				}
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeExternal()

				return err
			},
		},
		{
			name: "External_arbitrary",
			write: func(
				enc *per.Encoder,
				size int,
			) func() error {
				var (
					bits  = per.ExternalEncoding_Arbitrary(_P8Bits(size * 8))
					value = &per.External{
						Identification: ident(),
						Encoding: &per.ExternalEncoding{
							Choices: &bits,
						},
					}
				)

				return func() error {
					return enc.EncodeExternal(value)
				}
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeExternal()

				return err
			},
		},
		{
			name: "InstanceOf",
			write: func(
				enc *per.Encoder,
				size int,
			) func() error {
				value := &per.InstanceOf{
					TypeID: []int{
						1,
						3,
						6,
						1,
						4,
						1,
						99,
						1,
					},
					Value: _FragmentOctets(size),
				}

				return func() error {
					return enc.EncodeInstanceOf(value)
				}
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeInstanceOf()

				return err
			},
		},
	}
}

// TestAllocs_Encode measures the encoders: the allocations of an encoder that writes a BOOLEAN
// and then the value, less those of an encoder that writes the BOOLEAN only. The measurement
// is of the codec, not of the buffer: the value is small (3 octets), so the buffer that the
// writer starts with holds it. The expected figure is ALLOC_ENCODE_MAX (none).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestAllocs_Encode(t *testing.T) {
	for _, tc := range _P8AllocCases() {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"_"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					enc := ENCODERS[aligned]()

					if err := enc.EncodeBoolean(true); err != nil {
						t.Fatalf(
							"EncodeBoolean = %v",
							err,
						)
					}

					if err := tc.write(
						enc,
						P8_ALLOC_SHORT,
					)(); err != nil {
						t.Fatalf(
							"write = %v",
							err,
						)
					}

					base := testing.AllocsPerRun(
						ALLOC_RUNS,
						func() {
							enc := ENCODERS[aligned]()
							_ = enc.EncodeBoolean(true)
						},
					)
					enc = ENCODERS[aligned]()

					var (
						write = tc.write(
							enc,
							P8_ALLOC_SHORT,
						)
						total = testing.AllocsPerRun(
							ALLOC_RUNS,
							func() {
								enc := ENCODERS[aligned]()
								_ = enc.EncodeBoolean(true)
								_ = write()
							},
						)
					)

					t.Logf(
						"encode: %.0f allocations beyond the BOOLEAN",
						total-base,
					)

					if got := total - base; got > ALLOC_ENCODE_MAX {
						t.Errorf(
							"encode: %.0f allocations, max %d",
							got,
							ALLOC_ENCODE_MAX,
						)
					}
				},
			)
		}
	}
}

// TestAllocs_Decode counts the allocations of the decoders and checks that the count does not
// depend on the size of the value: the same count for 3 octets and for 300. A decoder returns
// structs, so some allocations are unavoidable (the value, the identification, its wrapper, the
// arcs of each object identifier, the data); the figure is logged, and the test fails only
// where a size makes the count grow, which an allocation for each octet, each fragment or each
// copy of the data would do.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func TestAllocs_Decode(t *testing.T) {
	for _, tc := range _P8AllocCases() {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"_"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					counts := map[int]float64{}

					for _, size := range []int{
						P8_ALLOC_SHORT,
						P8_ALLOC_LONG,
					} {
						enc := ENCODERS[aligned]()

						if err := enc.EncodeBoolean(true); err != nil {
							t.Fatalf(
								"EncodeBoolean = %v",
								err,
							)
						}

						if err := tc.write(
							enc,
							size,
						)(); err != nil {
							t.Fatalf(
								"write = %v",
								err,
							)
						}

						var (
							data = enc.Bytes()

							base = testing.AllocsPerRun(
								ALLOC_RUNS,
								func() {
									dec := DECODERS[aligned](
										data,
									)
									_, _ = dec.DecodeBoolean()
								},
							)
							total = testing.AllocsPerRun(
								ALLOC_RUNS,
								func() {
									dec := DECODERS[aligned](
										data,
									)
									_, _ = dec.DecodeBoolean()
									_ = tc.read(dec)
								},
							)
						)

						counts[size] = total - base
					}

					t.Logf(
						"decode: %.0f for %d octets, %.0f for %d",
						counts[P8_ALLOC_SHORT],
						P8_ALLOC_SHORT,
						counts[P8_ALLOC_LONG],
						P8_ALLOC_LONG,
					)

					if counts[P8_ALLOC_LONG] > counts[P8_ALLOC_SHORT] {
						t.Errorf(
							"decode grows: %.0f at %d, %.0f at %d",
							counts[P8_ALLOC_SHORT],
							P8_ALLOC_SHORT,
							counts[P8_ALLOC_LONG],
							P8_ALLOC_LONG,
						)
					}
				},
			)
		}
	}
}
