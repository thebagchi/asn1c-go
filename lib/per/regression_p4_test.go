package per_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_FRAGMENT is the kind key in testing.json of testing/fragment.py, which asks pycrate
// 0.8.1 and
// Erlang/OTP 29.1.1 for the encoding of each value. The file keeps the sha256 of
// each encoding, since the values are long.
const (
	VECTOR_FRAGMENT = "fragment"
)

type _P4Fragment struct {
	Type       string `json:"type"`
	Count      int    `json:"count"`
	Agree      bool   `json:"agree"`
	AperSha256 string `json:"aper_sha256"`
	UperSha256 string `json:"uper_sha256"`
	AperOctets int    `json:"aper_octets"`
	UperOctets int    `json:"uper_octets"`
}

type _P4FragmentFile struct {
	Fragment []*_P4Fragment `json:"fragment"`
}

// _FragmentCodec writes and reads one type at a given length.
type _FragmentCodec struct {
	write func(
		enc *per.Encoder,
		count int,
	) error
	read func(
		dec *per.Decoder,
		count int,
	) error
}

// FRAGMENT_CODECS holds the codec of each type in testing.json (fragment). All three are
// unconstrained, so the length is a semi-constrained whole number (X.691
// clause 11.9.3.8) and fragments from 16K.
var (
	FRAGMENT_CODECS = map[string]*_FragmentCodec{
		"Octets": {
			write: func(
				enc *per.Encoder,
				count int,
			) error {
				return enc.EncodeOctetString(
					_FragmentOctets(count),
					per.Unconstrained(),
				)
			},
			read: func(
				dec *per.Decoder,
				count int,
			) error {
				got, err := dec.DecodeOctetString(per.Unconstrained())
				if err == nil && !bytes.Equal(
					got,
					_FragmentOctets(count),
				) {
					return fmt.Errorf(
						"octets differ, got %d",
						len(got),
					)
				}

				return err
			},
		},
		"Bits": {
			write: func(
				enc *per.Encoder,
				count int,
			) error {
				return enc.EncodeBitString(
					&asn1.BitString{
						Bytes:     _FragmentBits(count),
						BitLength: count,
					},
					per.Unconstrained(),
				)
			},
			read: func(
				dec *per.Decoder,
				count int,
			) error {
				got, err := dec.DecodeBitString(per.Unconstrained())
				if err != nil {
					return err
				}

				if got.BitLength != count || !bytes.Equal(
					got.Bytes,
					_FragmentBits(count),
				) {
					return fmt.Errorf(
						"bits differ, got %d",
						got.BitLength,
					)
				}

				return nil
			},
		},
		"Text": {
			write: func(
				enc *per.Encoder,
				count int,
			) error {
				return enc.EncodeRestrictedString(
					_FragmentText(count),
					per.STRING_IA5,
					per.Unconstrained(),
				)
			},
			read: func(
				dec *per.Decoder,
				count int,
			) error {
				got, err := dec.DecodeRestrictedString(
					per.STRING_IA5,
					per.Unconstrained(),
				)
				if err == nil && got != _FragmentText(count) {
					return fmt.Errorf(
						"text differs, got %d characters",
						len(got),
					)
				}

				return err
			},
		},
	}
)

// TestRegression_P4FragmentTerminator guards the defect found in P4:
// _CloseFragments wrote the zero length of X.691 clause 11.9.3.8.3 after every
// value above 16K, so 16385 octets ended in a stray 00. The clause asks for that
// terminator only when the last fragment ends on a multiple of 16K, and the
// length 0 ends a value of 16384, 32768, 49152, 65536 octets. The expected
// encodings come from pycrate and OTP (testing/fragment.py): an unconstrained
// OCTET STRING, BIT STRING and IA5String (a known-multiplier string, 30.4) at
// lengths on both sides of each multiple. The test compares the sha256 of the
// encoding, decodes it, and writes the value between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 11:46: initial creation
func TestRegression_P4FragmentTerminator(t *testing.T) {
	var file _P4FragmentFile

	_Load(
		t,
		VECTOR_FRAGMENT,
		&file,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range file.Fragment {
			t.Run(
				fmt.Sprintf(
					"%s_%s_%d",
					VARIANT_NAMES[aligned],
					tc.Type,
					tc.Count,
				),
				func(t *testing.T) {
					var (
						codec = FRAGMENT_CODECS[tc.Type]
						want  = _Both(
							tc.AperSha256,
							tc.UperSha256,
						)[aligned]
						octets = map[bool]int{
							true:  tc.AperOctets,
							false: tc.UperOctets,
						}[aligned]

						enc = ENCODERS[aligned]()
					)
					if err := codec.write(
						enc,
						tc.Count,
					); err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					sum := sha256.Sum256(enc.Bytes())
					if got := hex.EncodeToString(sum[:]); got != want {
						t.Fatalf(
							"%d octets, sha256 %s, want %d, %s",
							len(enc.Bytes()),
							got,
							octets,
							want,
						)
					}

					if err := codec.read(
						DECODERS[aligned](enc.Bytes()),
						tc.Count,
					); err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return codec.write(
								enc,
								tc.Count,
							)
						},
						func(dec *per.Decoder) error {
							return codec.read(
								dec,
								tc.Count,
							)
						},
					)
				},
			)
		}
	}
}

// _FragmentOctets makes the OCTET STRING value of testing/fragment.py: octet i is
// (i*7 + 3) mod 256.
//
// Revisions:
//   - 2026-10-19 11:46: initial creation
func _FragmentOctets(count int) []byte {
	data := make(
		[]byte,
		count,
	)
	for index := range data {
		data[index] = byte(index*7 + 3)
	}

	return data
}

// _FragmentBits makes the octets of the BIT STRING value of testing/fragment.py:
// the octet rule above, with the unused bits of the last octet clear.
//
// Revisions:
//   - 2026-10-19 11:46: initial creation
func _FragmentBits(count int) []byte {
	data := _FragmentOctets((count + 7) / 8)
	if count%8 != 0 {
		data[len(data)-1] &= byte(0xFF << (8 - count%8))
	}

	return data
}

// _FragmentText makes the IA5String value of testing/fragment.py: character i is
// 'a' + i mod 26.
//
// Revisions:
//   - 2026-10-19 11:46: initial creation
func _FragmentText(count int) string {
	data := make(
		[]byte,
		count,
	)
	for index := range data {
		data[index] = byte('a' + index%26)
	}

	return string(data)
}
