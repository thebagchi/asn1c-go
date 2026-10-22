package per_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_ADDITIONS is the kind key in testing.json of testing/additions.py (pycrate 0.8.1 and
// Erlang/OTP 29.1.1; the types Additions-ExtBig and Fragments-Bits of testing.asn1).
const (
	VECTOR_ADDITIONS  = "additions"
	ADDITIONS_UNKNOWN = 5
)

type _P7AdditionsFile struct {
	Bitmap   []*_P7Row `json:"bitmap"`
	Sequence []*_P7Row `json:"sequence"`
}

// _P7AdditionsLoad reads testing.json (additions).
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func _P7AdditionsLoad(t *testing.T) *_P7AdditionsFile {
	t.Helper()

	var file _P7AdditionsFile

	_Load(
		t,
		VECTOR_ADDITIONS,
		&file,
	)

	return &file
}

// TestAdditions_LargeSequence checks a bitmap of more than 64 bits on ExtBig, a
// SEQUENCE with a BOOLEAN and 70 extension additions, with x1 only, x70 only, four
// of them, all, every third, and x65 only. X.691 11.9.3.4 gives a normally small
// length above 64 a 1 bit and an unconstrained length (11.9.3.6: one octet, here 70,
// octet-aligned in ALIGNED), then the bits; 19.9 gives each present addition an open
// type (01 80 for a BOOLEAN). UPER: OTP follows the clauses and is taken; pycrate
// differs. APER: neither oracle follows 11.9.3.6 (OTP writes the length n in a 10-bit
// field behind the pad, pycrate another form), so the expected octets are built from
// the clauses and the oracles' BIT STRING answers: e0 (ext bit, a, the 1 bit and the
// pad), the BIT STRING octets of both oracles for the 70 bits, and 01 80 for each
// present addition (testing/additions.py keeps every answer). The current code gives
// exactly these octets, which is the check of the derivation that
// TestRegression_P7AdditionsFragmented uses for bitmaps of 16K bits or more.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
//   - 2026-10-19 14:53: APER expected octets derived from the BIT STRING answers
func TestAdditions_LargeSequence(t *testing.T) {
	file := _P7AdditionsLoad(t)

	_P7SequenceVectors(
		t,
		file.Sequence,
	)
}

// _P7AdditionsBits makes the bitmap of n bits that testing/additions.py uses: the
// bit rule of fragment.py.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func _P7AdditionsBits(count int) *asn1.BitString {
	return &asn1.BitString{
		Bytes:     _FragmentBits(count),
		BitLength: count,
	}
}

// TestRegression_P7AdditionsFragmented guards review P7-7: EncodeAdditions and
// DecodeAdditions refused a bitmap of 16K bits or more (ErrLengthFragmented), and
// X.691 allows it. 19.8 invokes 11.9 with a normally small length; for n > 64,
// 11.9.3.4 writes a bit 1 and then n as an unconstrained length "according to the
// procedures of 11.9.3.5 to 11.9.3.8.4", so a length of 16K or more has fragments
// of 1 to 4 times 16K bits and, at an exact multiple, the terminator 00
// (11.9.3.8.3). That is an unconstrained BIT STRING of the same n bits behind one
// leading 1 bit. testing/additions.py asks pycrate and OTP for the BIT STRING and
// builds the expected octets: in APER the unconstrained length is octet-aligned
// (11.9.3.6), so the 1 bit is followed by 7 zero pad bits, which is the octet 80,
// and then the BIT STRING octets; in UPER the BIT STRING bits follow the 1 bit
// with no pad, and the last octet is padded with 0 bits. The rows of 65, 70 and
// 100 bits (hex in the file) hold the same derivation where the code already
// answers, and TestAdditions_LargeSequence checks it against the oracles on a
// SEQUENCE. Rows: 16384, 16385, 32768, 65536, 65537 and 70000 bits, with the bit
// rule of fragment.py. Each is encoded, decoded with a known part of n - 5 bits
// (the decoder returns the number of present bits in the last 5), and written
// between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func TestRegression_P7AdditionsFragmented(t *testing.T) {
	file := _P7AdditionsLoad(t)

	for _, aligned := range []bool{true, false} {
		for _, row := range file.Bitmap {
			t.Run(
				fmt.Sprintf(
					"%s_%d",
					VARIANT_NAMES[aligned],
					*row.Count,
				),
				func(t *testing.T) {
					var (
						bits = _P7AdditionsBits(*row.Count)
						enc  = ENCODERS[aligned]()
					)

					if err := enc.EncodeAdditions(bits); err != nil {
						t.Fatalf(
							"EncodeAdditions(%d bits) = %v",
							*row.Count,
							err,
						)
					}

					_P7Check(
						t,
						row,
						aligned,
						enc.Bytes(),
					)

					var (
						read = func(dec *per.Decoder) error {
							return _P7ReadAdditions(
								dec,
								bits,
							)
						}

						dec = DECODERS[aligned](enc.Bytes())
					)

					if err := read(dec); err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeAdditions(bits)
						},
						read,
					)
				},
			)
		}
	}
}

// _P7ReadAdditions decodes a bitmap with a known part of all but the last
// ADDITIONS_UNKNOWN bits, and checks the known bits and the count of present bits
// beyond them.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func _P7ReadAdditions(
	dec *per.Decoder,
	want *asn1.BitString,
) error {
	var (
		known = _P7Bits(want.BitLength - ADDITIONS_UNKNOWN)

		unknown, err = dec.DecodeAdditions(known)
	)
	if err != nil {
		return err
	}

	present := uint64(0)

	for index := 0; index < want.BitLength; index++ {
		switch {
		case index < known.BitLength && known.At(index) != want.At(index):
			return fmt.Errorf(
				"known bit %d differs",
				index,
			)
		case index >= known.BitLength && want.At(index) == 1:
			present++
		}
	}

	if unknown != present {
		return fmt.Errorf(
			"%d unknown additions, want %d",
			unknown,
			present,
		)
	}

	return nil
}

// TestRegression_P7AdditionsNoPartialWrite guards the second half of P7-7: when
// EncodeAdditions fails it leaves the encoder as it was. The input is nil, bits
// whose Bytes hold fewer than BitLength bits, or no bits; the encoder holds a
// BOOLEAN first. After the error the octets are unchanged and the encoder goes on
// to write the same following BOOLEAN as an encoder that never saw the call.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func TestRegression_P7AdditionsNoPartialWrite(t *testing.T) {
	short := _P7Bits(9)
	short.Bytes = short.Bytes[:1]

	cases := map[string]*asn1.BitString{
		"nil":     nil,
		"short":   short,
		"no_bits": _P7Bits(0),
	}

	for _, aligned := range []bool{true, false} {
		for name, input := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+name,
				func(t *testing.T) {
					var (
						enc     = ENCODERS[aligned]()
						control = ENCODERS[aligned]()
					)

					for _, one := range []*per.Encoder{enc, control} {
						if err := one.EncodeBoolean(true); err != nil {
							t.Fatalf(
								"EncodeBoolean = %v",
								err,
							)
						}
					}

					if err := enc.EncodeAdditions(input); err == nil {
						t.Fatalf(
							"EncodeAdditions(%s) = nil, want an error",
							name,
						)
					}

					if err := enc.EncodeBoolean(true); err != nil {
						t.Fatalf(
							"EncodeBoolean = %v",
							err,
						)
					}

					if err := control.EncodeBoolean(true); err != nil {
						t.Fatalf(
							"EncodeBoolean = %v",
							err,
						)
					}

					if !bytes.Equal(
						enc.Bytes(),
						control.Bytes(),
					) {
						t.Fatalf(
							"after the error % x, want % x",
							enc.Bytes(),
							control.Bytes(),
						)
					}
				},
			)
		}
	}
}

// TestRegression_P7EmptyAdditions pins the sentinel of the empty bitmap: both
// EncodeAdditions of no bits and DecodeAdditions of a length of 0 (a 1 bit and
// the unconstrained length 00, which no encoder writes: 19.8 note, n cannot be
// zero) report per.ErrEmptyAdditions, not ErrLengthFragmented or a range error.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func TestRegression_P7EmptyAdditions(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned],
			func(t *testing.T) {
				err := ENCODERS[aligned]().EncodeAdditions(_P7Bits(0))
				if !errors.Is(
					err,
					per.ErrEmptyAdditions,
				) {
					t.Errorf(
						"EncodeAdditions(0 bits) = %v, want ErrEmpty",
						err,
					)
				}

				dec := DECODERS[aligned]([]byte{0x80, 0x00})

				_, err = dec.DecodeAdditions(_P7Bits(3))
				if !errors.Is(
					err,
					per.ErrEmptyAdditions,
				) {
					t.Errorf(
						"DecodeAdditions(0) = %v, want ErrEmpty",
						err,
					)
				}
			},
		)
	}
}
