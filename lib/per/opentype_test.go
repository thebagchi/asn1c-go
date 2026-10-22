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

// _P7Fragments returns the rows of testing/fragment.py for one type.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Fragments(
	t *testing.T,
	kind string,
) []*_P4Fragment {
	t.Helper()

	var file _P4FragmentFile

	_Load(
		t,
		VECTOR_FRAGMENT,
		&file,
	)

	var rows []*_P4Fragment

	for _, row := range file.Fragment {
		if row.Type == kind {
			rows = append(
				rows,
				row,
			)
		}
	}

	return rows
}

// _P7FragmentWant returns the sha256 and the length that a fragment row gives
// for a variant.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7FragmentWant(
	row *_P4Fragment,
	aligned bool,
) (string, int) {
	want := map[bool]*_P7Expected{
		true: {
			sha256: row.AperSha256,
			octets: row.AperOctets,
		},
		false: {
			sha256: row.UperSha256,
			octets: row.UperOctets,
		},
	}[aligned]

	return want.sha256, want.octets
}

// _P7Sha reports an encoding that differs from the sha256 and the length of a
// fragment row.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Sha(
	t *testing.T,
	got []byte,
	sha string,
	octets int,
) {
	t.Helper()

	sum := sha256.Sum256(got)

	if text := hex.EncodeToString(sum[:]); text != sha || len(got) != octets {
		t.Fatalf(
			"%d octets, sha256 %s, want %d, %s",
			len(got),
			text,
			octets,
			sha,
		)
	}
}

// TestOpenType_Fragments checks EncodeOpenType and DecodeOpenType against the
// encodings of an unconstrained OCTET STRING that pycrate and OTP agree on
// (testing/fragment.py), at the lengths of 1, 16383, 16384, 16385, 32768, 32769,
// 49152, 65535, 65536, 65537 and 70000 octets. X.691 11.2.2 adds an unconstrained
// length in octets and an octet-aligned bit-field with the inner encoding, so an
// open type is that OCTET STRING, with the fragmentation and the terminator of
// 11.9.3.8. The inner value is the octet rule of fragment.py. The result is also
// read with SkipOpenTypes, and written between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestOpenType_Fragments(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		for _, row := range _P7Fragments(
			t,
			"Octets",
		) {
			if row.Count == 0 {
				continue
			}

			t.Run(
				fmt.Sprintf(
					"%s_%d",
					VARIANT_NAMES[aligned],
					row.Count,
				),
				func(t *testing.T) {
					var (
						inner = _FragmentOctets(row.Count)
						enc   = ENCODERS[aligned]()
					)

					if err := enc.EncodeOpenType(inner); err != nil {
						t.Fatalf(
							"EncodeOpenType = %v",
							err,
						)
					}

					sha, octets := _P7FragmentWant(
						row,
						aligned,
					)

					_P7Sha(
						t,
						enc.Bytes(),
						sha,
						octets,
					)
					_P7OpenTypeRead(
						t,
						aligned,
						enc.Bytes(),
						inner,
					)
					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return enc.EncodeOpenType(inner)
						},
						func(dec *per.Decoder) error {
							got, err := dec.DecodeOpenType()
							if err == nil && !bytes.Equal(
								got,
								inner,
							) {
								return fmt.Errorf(
									"open type of %d octets",
									len(got),
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

// _P7OpenTypeRead decodes the open type of data, and skips it with a second
// decoder.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7OpenTypeRead(
	t *testing.T,
	aligned bool,
	data,
	want []byte,
) {
	t.Helper()

	got, err := DECODERS[aligned](data).DecodeOpenType()
	if err != nil || !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"DecodeOpenType = %d octets, %v, want %d octets",
			len(got),
			err,
			len(want),
		)
	}

	dec := DECODERS[aligned](append(
		append(
			[]byte{},
			data...,
		),
		0,
	))

	if err := dec.SkipOpenTypes(1); err != nil {
		t.Fatalf(
			"SkipOpenTypes(1) = %v",
			err,
		)
	}
}

// TestOpenType_Skip writes a BOOLEAN, three open types of 1, 130 and 16385 octets
// (the length forms of X.691 11.9.3.6, 11.9.3.7 and 11.9.3.8), and a BOOLEAN. A
// decoder skips none, one, two, or three of them with SkipOpenTypes and reads the
// rest with DecodeOpenType and the BOOLEAN after the last. The skip needs no copy
// and ends at the bit where the next field starts (11.2.2, 19.9).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestOpenType_Skip(t *testing.T) {
	inners := [][]byte{
		_FragmentOctets(1),
		_FragmentOctets(130),
		_FragmentOctets(16385),
	}

	for _, aligned := range []bool{true, false} {
		for skip := range len(inners) + 1 {
			t.Run(
				fmt.Sprintf(
					"%s_skip_%d",
					VARIANT_NAMES[aligned],
					skip,
				),
				func(t *testing.T) {
					_P7CheckSkip(
						t,
						aligned,
						inners,
						skip,
					)
				},
			)
		}
	}
}

// _P7CheckSkip writes the open types between BOOLEAN fields and reads them,
// skipping the first skip of them.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7CheckSkip(
	t *testing.T,
	aligned bool,
	inners [][]byte,
	skip int,
) {
	t.Helper()

	enc := ENCODERS[aligned]()

	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatalf(
			"EncodeBoolean = %v",
			err,
		)
	}

	for _, inner := range inners {
		if err := enc.EncodeOpenType(inner); err != nil {
			t.Fatalf(
				"EncodeOpenType = %v",
				err,
			)
		}
	}

	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatalf(
			"EncodeBoolean = %v",
			err,
		)
	}

	dec := DECODERS[aligned](enc.Bytes())

	if first, err := dec.DecodeBoolean(); err != nil || !first {
		t.Fatalf(
			"DecodeBoolean = %v, %v",
			first,
			err,
		)
	}

	if err := dec.SkipOpenTypes(uint64(skip)); err != nil {
		t.Fatalf(
			"SkipOpenTypes(%d) = %v",
			skip,
			err,
		)
	}

	for _, inner := range inners[skip:] {
		got, err := dec.DecodeOpenType()
		if err != nil || !bytes.Equal(
			got,
			inner,
		) {
			t.Fatalf(
				"DecodeOpenType = %d octets, %v, want %d",
				len(got),
				err,
				len(inner),
			)
		}
	}

	if last, err := dec.DecodeBoolean(); err != nil || !last {
		t.Fatalf(
			"DecodeBoolean(trailer) = %v, %v",
			last,
			err,
		)
	}
}

// TestOpenType_Nested checks Nested: a new Encoder of the same variant that holds
// the inner value, apart from the one that made it. The complete encoding of
// nothing is one octet 00 (X.691 11.1.3, 11.2.1), and one BOOLEAN true is 80.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestOpenType_Nested(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned],
			func(t *testing.T) {
				var (
					outer = ENCODERS[aligned]()
					inner = outer.Nested()
				)

				if inner == outer || inner.Aligned() != aligned {
					t.Fatalf(
						"Nested() = %p (aligned %v), outer %p",
						inner,
						inner.Aligned(),
						outer,
					)
				}

				if got := inner.Bytes(); !bytes.Equal(
					got,
					[]byte{0},
				) {
					t.Fatalf(
						"empty nested encoding % x, want 00",
						got,
					)
				}

				if err := inner.EncodeBoolean(true); err != nil {
					t.Fatalf(
						"EncodeBoolean = %v",
						err,
					)
				}

				if got := inner.Bytes(); !bytes.Equal(
					got,
					[]byte{0x80},
				) {
					t.Fatalf(
						"nested encoding % x, want 80",
						got,
					)
				}

				if got := outer.Bytes(); !bytes.Equal(
					got,
					[]byte{0},
				) {
					t.Fatalf(
						"the outer encoder holds % x, want 00",
						got,
					)
				}
			},
		)
	}
}

// TestPreamble_Large checks EncodePreamble and DecodePreamble for the bit counts
// of testing/fragment.py. X.691 19.3: below 64K bits the bitmap is a bit-field
// without a length, so the octets are the bits themselves (checked against the
// bit rule of fragment.py); from 64K bits the procedures of 11.9 give it a length
// of n bits and fragment it, which are the procedures of an unconstrained BIT
// STRING, so the answer of pycrate and OTP for a BIT STRING of the same bits
// (the sha256 of testing.json (fragment), 65536, 65537 and 70000 bits) is the expectation.
// No oracle encodes a SEQUENCE with 64K OPTIONAL components. The bits are read
// back and the value is written between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestPreamble_Large(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		for _, row := range _P7Fragments(
			t,
			"Bits",
		) {
			if row.Count == 0 {
				continue
			}

			t.Run(
				fmt.Sprintf(
					"%s_%d",
					VARIANT_NAMES[aligned],
					row.Count,
				),
				func(t *testing.T) {
					_P7CheckPreamble(
						t,
						aligned,
						row,
					)
				},
			)
		}
	}
}

// _P7CheckPreamble encodes the bits of a fragment row as a preamble and checks
// the octets, the decode and the frame.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7CheckPreamble(
	t *testing.T,
	aligned bool,
	row *_P4Fragment,
) {
	t.Helper()

	var (
		bits = &asn1.BitString{
			Bytes:     _FragmentBits(row.Count),
			BitLength: row.Count,
		}
		enc = ENCODERS[aligned]()
	)

	if err := enc.EncodePreamble(bits); err != nil {
		t.Fatalf(
			"EncodePreamble = %v",
			err,
		)
	}

	if row.Count >= per.FRAGMENT_SIZE*4 {
		sha, octets := _P7FragmentWant(
			row,
			aligned,
		)

		_P7Sha(
			t,
			enc.Bytes(),
			sha,
			octets,
		)
	} else {
		_Compare(
			t,
			enc.Bytes(),
			_FragmentBits(row.Count),
		)
	}

	read := func(dec *per.Decoder) error {
		got := _P7Bits(row.Count)

		if err := dec.DecodePreamble(got); err != nil {
			return err
		}

		if !bytes.Equal(
			got.Bytes,
			bits.Bytes,
		) {
			return fmt.Errorf(
				"%d bits read differ",
				row.Count,
			)
		}

		return nil
	}

	if err := read(DECODERS[aligned](enc.Bytes())); err != nil {
		t.Fatalf(
			"decode = %v",
			err,
		)
	}

	_CheckFramed(
		t,
		aligned,
		func(enc *per.Encoder) error {
			return enc.EncodePreamble(bits)
		},
		read,
	)
}
