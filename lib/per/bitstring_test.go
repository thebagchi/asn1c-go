package per_test

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// BITSTRING_LONG is the length of the long row: one AVX2 decode block, so the
// kernels take it whole. BITSTRING_PATTERN repeats to fill it. BITSTRING_HIGH_BIT
// is bit 0 of an octet.
const (
	BITSTRING_LONG     = 64
	BITSTRING_PATTERN  = "1011000111"
	BITSTRING_HIGH_BIT = 0x80
)

// _TextRow is one row of TestBitString_Text: the text, and the octets and the bit
// length it stands for.
type _TextRow struct {
	name   string
	text   string
	octets string
	length int
}

// TestBitString_Text guards review P31: each text parses to its octets and bit
// length, the octets print back as the text, and a one-bit oracle agrees with both.
// Character i is bit i, the high bit of the first octet first; the unused low bits
// of the last octet are 0.
//
// Revisions:
//   - 2026-10-21 21:38: initial creation (review P31)
func TestBitString_Text(t *testing.T) {
	var (
		long = strings.Repeat(
			BITSTRING_PATTERN,
			BITSTRING_LONG/len(BITSTRING_PATTERN)+1,
		)[:BITSTRING_LONG]
		rows = []*_TextRow{
			{
				name: "empty",
			},
			{
				name:   "zero",
				text:   "0",
				octets: "00",
				length: 1,
			},
			{
				name:   "one",
				text:   "1",
				octets: "80",
				length: 1,
			},
			{
				name:   "three",
				text:   "101",
				octets: "a0",
				length: 3,
			},
			{
				name:   "octet",
				text:   "10110001",
				octets: "b1",
				length: 8,
			},
			{
				name:   "nine",
				text:   "101100011",
				octets: "b180",
				length: 9,
			},
			{
				name:   "long",
				text:   long,
				octets: hex.EncodeToString(_OneBitOctets(long)),
				length: BITSTRING_LONG,
			},
		}
	)

	for _, row := range rows {
		t.Run(
			row.name,
			func(t *testing.T) {
				_CheckTextRow(
					t,
					row,
				)
			},
		)
	}
}

// TestBitString_BadCharacter guards review P31: a character other than '0' or '1'
// returns the zero value and an error that names its index, at the start, in the
// middle and at the end, in a short text and in one that the kernels read. A space
// is such a character.
//
// Revisions:
//   - 2026-10-21 21:38: initial creation (review P31)
func TestBitString_BadCharacter(t *testing.T) {
	var (
		long = strings.Repeat(
			"01",
			BITSTRING_LONG,
		)
		cases = []struct {
			name  string
			text  string
			index int
		}{
			{
				name:  "short_start",
				text:  "x0110",
				index: 0,
			},
			{
				name:  "short_middle",
				text:  "01 10",
				index: 2,
			},
			{
				name:  "short_end",
				text:  "01102",
				index: 4,
			},
			{
				name:  "long_start",
				text:  "2" + long[1:],
				index: 0,
			},
			{
				name:  "long_middle",
				text:  long[:BITSTRING_LONG+3] + " " + long[BITSTRING_LONG+4:],
				index: BITSTRING_LONG + 3,
			},
			{
				name:  "long_end",
				text:  long[:len(long)-1] + "a",
				index: len(long) - 1,
			},
		}
	)

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				_CheckBadText(
					t,
					tc.text,
					tc.index,
				)
			},
		)
	}
}

// TestBitString_Refusals guards review P31: FormatBitString refuses a nil value, a
// negative length and a short octet slice with the errors the package uses for
// them, and returns no text.
//
// Revisions:
//   - 2026-10-21 21:38: initial creation (review P31)
func TestBitString_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		value *asn1.BitString
		want  error
	}{
		{
			name: "nil",
			want: per.ErrNilValue,
		},
		{
			name: "negative",
			value: &asn1.BitString{
				BitLength: -1,
			},
			want: per.ErrValueOutOfRange,
		},
		{
			name: "short",
			value: &asn1.BitString{
				Bytes: []byte{
					0xFF,
				},
				BitLength: 9,
			},
			want: per.ErrShortBitString,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				text, err := per.FormatBitString(tc.value)
				if text != "" || !errors.Is(
					err,
					tc.want,
				) {
					t.Fatalf(
						"FormatBitString = %q, %v; want \"\", %v",
						text,
						err,
						tc.want,
					)
				}
			},
		)
	}
}

// _CheckTextRow parses the text of a row, compares it with the row and with the
// one-bit oracle, and prints it back.
//
// Revisions:
//   - 2026-10-21 21:38: initial creation
func _CheckTextRow(
	t *testing.T,
	row *_TextRow,
) {
	t.Helper()

	value, err := per.ParseBitString(row.text)
	if err != nil {
		t.Fatal(err)
	}

	var (
		got    = hex.EncodeToString(value.Bytes)
		oracle = hex.EncodeToString(_OneBitOctets(row.text))
	)

	if got != row.octets || got != oracle || value.BitLength != row.length {
		t.Fatalf(
			"ParseBitString(%q) = %s, %d bits; want %s (oracle %s), %d bits",
			row.text,
			got,
			value.BitLength,
			row.octets,
			oracle,
			row.length,
		)
	}

	text, err := per.FormatBitString(&value)
	if err != nil || text != row.text {
		t.Fatalf(
			"FormatBitString = %q, %v; want %q",
			text,
			err,
			row.text,
		)
	}
}

// _CheckBadText parses a text with one bad character and checks the zero value
// and the index in the error.
//
// Revisions:
//   - 2026-10-21 21:38: initial creation
func _CheckBadText(
	t *testing.T,
	text string,
	index int,
) {
	t.Helper()

	value, err := per.ParseBitString(text)
	if !errors.Is(
		err,
		per.ErrInvalidBinary,
	) {
		t.Fatalf(
			"error = %v, want ErrInvalidBinary",
			err,
		)
	}

	want := "at index " + strconv.Itoa(index) + ":"
	if !strings.Contains(
		err.Error(),
		want,
	) {
		t.Fatalf(
			"error %q does not say %q",
			err,
			want,
		)
	}

	if value.BitLength != 0 || value.Bytes != nil {
		t.Fatalf(
			"value = %v, want the zero value",
			value,
		)
	}
}

// _OneBitOctets is the oracle: it sets one bit per '1' character, character i at
// bit i, the high bit of the first octet first.
//
// Revisions:
//   - 2026-10-21 21:38: initial creation
func _OneBitOctets(text string) []byte {
	octets := make(
		[]byte,
		(len(text)+per.BITS_PER_BYTE-1)/per.BITS_PER_BYTE,
	)

	for idx := range len(text) {
		if text[idx] == per.BINARY_ONE {
			shift := idx % per.BITS_PER_BYTE
			octets[idx/per.BITS_PER_BYTE] |= BITSTRING_HIGH_BIT >> shift
		}
	}

	return octets
}
