package per_test

import (
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestExtension_Vectors checks the extension primitives against the octets of
// pycrate and OTP for Ext1 (one addition), Ext2 (four additions: c, d, g and
// the group [[ e, f ]], with b of the root OPTIONAL), ExtT1 (a root component
// after the second extension marker) and ExtN (an addition of type NULL whose
// open type holds the one octet 00 of X.691 11.1.3). Values have no additions,
// some, or all of them. X.691 19.1 writes the extension bit, 19.7 and 19.8 the
// bitmap of one bit for each addition of the type after a normally small length
// (11.9.3.4), not aligned in ALIGNED, and 19.9 each present addition as an open
// type (11.2), a group as a SEQUENCE with its own preamble. pycrate pads the
// APER bitmap and sends the trailer of ExtT1 as an addition; OTP follows the
// clauses and is taken (testing/composites.py keeps both answers).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestExtension_Vectors(t *testing.T) {
	file := _P7Load(t)

	_P7SequenceVectors(
		t,
		file.Extension,
	)
}

// TestExtension_Framed writes the rows between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestExtension_Framed(t *testing.T) {
	file := _P7Load(t)

	_P7SequenceFramed(
		t,
		file.Extension,
	)
}

// TestExtension_OlderDecoder decodes the encodings of Ext2 with the codec of
// Ext1, which knows the addition c only. DecodeAdditions fills the one known
// bit and returns the number of the present additions beyond it; the codec
// reads c from its open type and SkipOpenTypes skips the others (X.691 19.7
// note, 11.2). The BOOLEAN after the value is read correctly in both variants,
// which shows that the skip ended at the right bit. The decoded value is the
// part of the Ext2 value that Ext1 knows.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestExtension_OlderDecoder(t *testing.T) {
	var (
		file    = _P7Load(t)
		newer   = P7_SEQUENCES["Ext2"]
		older   = P7_SEQUENCES["Ext1"]
		skipped = 0
	)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P7Of(
			file.Extension,
			"Ext2",
		) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						value = _P7Parse(
							t,
							newer,
							row.Value,
						)
						unknown = uint64(_P7Additions(
							newer,
							value,
						) - _P7Additions(
							older,
							value,
						))
					)

					if unknown > 0 {
						skipped++
					}

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return _P7EncodeSequence(
								enc,
								newer,
								value,
							)
						},
						func(dec *per.Decoder) error {
							got, count, err := _P7DecodeSequence(
								dec,
								older,
							)
							if err != nil {
								return err
							}

							if count != unknown {
								t.Errorf(
									"unknown = %d, want %d",
									count,
									unknown,
								)
							}

							_P7Equal(
								t,
								got,
								_P7Normal(
									older,
									value,
								),
							)

							return nil
						},
					)

					got, count, err := _P7DecodeSequence(
						DECODERS[aligned](_Unhex(
							t,
							_P7Want(
								row,
								aligned,
							).hex,
						)),
						older,
					)
					if err != nil || count != unknown {
						t.Fatalf(
							"oracle octets: %v, %d unknown, %v",
							got,
							count,
							err,
						)
					}
				},
			)
		}
	}

	if skipped == 0 {
		t.Fatalf("no row of Ext2 has an addition that Ext1 does not know")
	}
}

// TestExtension_NewerDecoder decodes the encodings of Ext1 with the codec of
// Ext2. The bitmap of Ext1 has one bit, the decoder of Ext2 knows four: it
// fills the bit it was sent, the other three are 0 and no addition is unknown.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestExtension_NewerDecoder(t *testing.T) {
	var (
		file  = _P7Load(t)
		older = P7_SEQUENCES["Ext1"]
		newer = P7_SEQUENCES["Ext2"]
	)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P7Of(
			file.Extension,
			"Ext1",
		) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					got, count, err := _P7DecodeSequence(
						DECODERS[aligned](_Unhex(
							t,
							_P7Want(
								row,
								aligned,
							).hex,
						)),
						newer,
					)
					if err != nil || count != 0 {
						t.Fatalf(
							"decode = %v, %d unknown, %v",
							got,
							count,
							err,
						)
					}

					_P7Equal(
						t,
						got,
						_P7Normal(
							newer,
							_P7Parse(
								t,
								older,
								row.Value,
							),
						),
					)
				},
			)
		}
	}
}

// TestExtension_LargeBitmap checks the bitmap of 65 and 130 additions, which
// X.691 19.8 and 11.9.3.4 give a length in the form of an unconstrained length
// (a 1 bit, then the length, octet-aligned in ALIGNED). No oracle can encode a
// SEQUENCE of that size in a test, so the check is the round trip with the
// BOOLEAN fields around it, the number of octets that the clauses give (UPER
// 1 + 8 or 16 + n bits; APER 1 bit, padding to the octet, 8 or 16 bits of length, n bits)
// and the count of unknown additions when the decoder knows fewer.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestExtension_LargeBitmap(t *testing.T) {
	sizes := map[int]map[bool]int{
		65: {
			true:  11,
			false: 10,
		},
		130: {
			true:  20,
			false: 19,
		},
	}

	for _, aligned := range []bool{true, false} {
		for count, octets := range sizes {
			t.Run(
				fmt.Sprintf(
					"%s_%d",
					VARIANT_NAMES[aligned],
					count,
				),
				func(t *testing.T) {
					bits := _P7Bits(count)

					for _, index := range []int{0, 7, count - 2, count - 1} {
						_P7Mark(
							bits,
							index,
						)
					}

					enc := ENCODERS[aligned]()
					if err := enc.EncodeAdditions(bits); err != nil {
						t.Fatalf(
							"EncodeAdditions = %v",
							err,
						)
					}

					if got := len(enc.Bytes()); got != octets[aligned] {
						t.Fatalf(
							"%d bits: %d octets, want %d",
							count,
							got,
							octets[aligned],
						)
					}

					var (
						known = _P7Bits(count - 3)
						dec   = DECODERS[aligned](enc.Bytes())

						unknown, err = dec.DecodeAdditions(known)
					)

					if err != nil || unknown != 2 {
						t.Fatalf(
							"DecodeAdditions = %d, %v, want 2",
							unknown,
							err,
						)
					}
				},
			)
		}
	}
}
