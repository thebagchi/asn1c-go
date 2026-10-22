package per_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// P29_LONG is the length of the long rows: past one AVX2 block and not a multiple of eight,
// so a decoder that reads words has a tail. P29_SHORT is the longest of the short lengths,
// past two words. P29_OFFSETS is the number of BOOLEAN bits in front, 0 to 7. P29_CHARS
// holds characters of every one of the three alphabets.
const (
	P29_LONG    = 70
	P29_SHORT   = 17
	P29_OFFSETS = 8
	P29_CHARS   = "AZaz09 '()+,-./:=?"
)

// P29_LENGTHS are the lengths past P29_SHORT: each side of one 64-character septet chunk,
// and two chunks with a tail.
var (
	P29_LENGTHS = []int{
		63,
		64,
		65,
		130,
	}
)

// _P29Trip is one case of TestRegression_P29RoundTrip: the variant, the kind, the text, and
// the BOOLEAN bits in front of it.
type _P29Trip struct {
	aligned bool
	kind    per.StringKind
	text    string
	offset  int
}

// _P29Row is one row of TestRegression_P29BadCharacter: a text that IA5String accepts, the
// kind that must refuse it, and the error that kind gives.
type _P29Row struct {
	name  string
	text  string
	kind  per.StringKind
	error string
}

// TestRegression_P29BadCharacter guards review P29-1: a decoder that reads the characters of a
// string in one pass must refuse a bad character with the error the per-character path gave.
// Each text is encoded as an IA5String, which holds every byte below 0x80, and decoded as a
// kind whose alphabet lacks one of its characters. The rows put that character first, inside
// the first word, and at the end of a long text.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func TestRegression_P29BadCharacter(t *testing.T) {
	var (
		long = strings.Repeat(
			"A",
			P29_LONG-1,
		)
		rows = []*_P29Row{
			{
				name:  "visible_first",
				text:  "\x01BCDEFGHIJ",
				kind:  per.STRING_VISIBLE,
				error: "value 1: character is not in the type's alphabet",
			},
			{
				name:  "visible_delete",
				text:  "ABCDEF\x7fH",
				kind:  per.STRING_VISIBLE,
				error: "value 127: character is not in the type's alphabet",
			},
			{
				name:  "visible_long",
				text:  long + "\x1f",
				kind:  per.STRING_VISIBLE,
				error: "value 31: character is not in the type's alphabet",
			},
			{
				name:  "printable_at",
				text:  "A@BCDEFGH",
				kind:  per.STRING_PRINTABLE,
				error: "'@': character is not in the type's alphabet",
			},
			{
				name:  "printable_long",
				text:  long + "*",
				kind:  per.STRING_PRINTABLE,
				error: "'*': character is not in the type's alphabet",
			},
		}
	)

	for _, row := range rows {
		for _, aligned := range []bool{true, false} {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+row.name,
				func(t *testing.T) {
					_CheckBadCharacter(
						t,
						aligned,
						row,
					)
				},
			)
		}
	}
}

// _CheckBadCharacter encodes one row as an IA5String and decodes it as the kind of the row.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation
func _CheckBadCharacter(
	t *testing.T,
	aligned bool,
	row *_P29Row,
) {
	t.Helper()

	var (
		enc = ENCODERS[aligned]()

		err = enc.EncodeRestrictedString(
			row.text,
			per.STRING_IA5,
			per.Unconstrained(),
		)
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DECODERS[aligned](enc.Bytes()).DecodeRestrictedString(
		row.kind,
		per.Unconstrained(),
	)
	if err == nil || err.Error() != row.error {
		t.Fatalf(
			"error = %v, want %q",
			err,
			row.error,
		)
	}
}

// TestRegression_P29RoundTrip guards review P29-1: the one-pass decoders must read back what
// the encoder wrote, at every bit offset, with the stream at the right place after the
// string. A BOOLEAN after the string must still decode. The encoder is checked against the
// oracle vectors, so this checks the decoder.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func TestRegression_P29RoundTrip(t *testing.T) {
	var (
		kinds = map[string]per.StringKind{
			"ia5":       per.STRING_IA5,
			"visible":   per.STRING_VISIBLE,
			"printable": per.STRING_PRINTABLE,
		}

		lengths = make(
			[]int,
			0,
			P29_SHORT+1+len(P29_LENGTHS),
		)
	)
	for length := range P29_SHORT + 1 {
		lengths = append(
			lengths,
			length,
		)
	}

	lengths = append(
		lengths,
		P29_LENGTHS...,
	)

	for name, kind := range kinds {
		for _, aligned := range []bool{true, false} {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+name,
				func(t *testing.T) {
					for _, length := range lengths {
						for offset := range P29_OFFSETS {
							_CheckRoundTrip(
								t,
								&_P29Trip{
									aligned: aligned,
									kind:    kind,
									text:    _P29Text(length),
									offset:  offset,
								},
							)
						}
					}
				},
			)
		}
	}
}

// _CheckRoundTrip writes the BOOLEAN bits of one case, its text, and one more BOOLEAN, then
// reads them all back.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation
func _CheckRoundTrip(
	t *testing.T,
	trip *_P29Trip,
) {
	t.Helper()

	var (
		where = "length " + strconv.Itoa(len(trip.text)) +
			" offset " + strconv.Itoa(trip.offset)

		enc = ENCODERS[trip.aligned]()
	)
	for range trip.offset {
		if err := enc.EncodeBoolean(false); err != nil {
			t.Fatal(err)
		}
	}

	if err := enc.EncodeRestrictedString(
		trip.text,
		trip.kind,
		per.Unconstrained(),
	); err != nil {
		t.Fatalf(
			"%s: encode: %v",
			where,
			err,
		)
	}

	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatal(err)
	}

	dec := DECODERS[trip.aligned](enc.Bytes())
	for range trip.offset {
		if _, err := dec.DecodeBoolean(); err != nil {
			t.Fatal(err)
		}
	}

	back, err := dec.DecodeRestrictedString(
		trip.kind,
		per.Unconstrained(),
	)
	if err != nil || back != trip.text {
		t.Fatalf(
			"%s: decoded %q, %v; want %q",
			where,
			back,
			err,
			trip.text,
		)
	}

	last, err := dec.DecodeBoolean()
	if err != nil || !last {
		t.Fatalf(
			"%s: the BOOLEAN after the string = %t, %v; want true",
			where,
			last,
			err,
		)
	}
}

// _P29Text is length characters taken from P29_CHARS in turn.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation
func _P29Text(length int) string {
	text := make(
		[]byte,
		length,
	)
	for idx := range text {
		text[idx] = P29_CHARS[idx%len(P29_CHARS)]
	}

	return string(text)
}
