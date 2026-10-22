package per_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// How far the differential test looks, in bits: past several kernel blocks,
// through every partial byte.
const (
	BINARY_LENGTHS = 600
)

// The character positions an invalid character is planted at: the first, both
// sides of each kernel block boundary, and inside the tail.
var (
	BINARY_INVALID_AT = []int{0, 7, 8, 63, 64, 65, 127, 128, 300, 599}
)

// TestRegressionBinaryMatchesReference checks FormatBitString against the
// bit loop and ParseBitString against the bytes, at every bit length up
// to several blocks, including the lengths that end inside a byte. It covers
// lib/review.md §9.4.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
//   - 2026-10-21 21:38: FormatBitString and ParseBitString, which replaced BitStringToBinary
//     and BitStringFromBinary (review P31)
func TestRegressionBinaryMatchesReference(t *testing.T) {
	t.Parallel()

	for bits := range BINARY_LENGTHS + 1 {
		t.Run(
			strconv.Itoa(bits),
			func(t *testing.T) {
				t.Parallel()

				var (
					value    = _BitString(bits)
					want     = _BinaryReference(value)
					got, err = per.FormatBitString(value)
				)

				if err != nil || got != want {
					t.Fatalf(
						"FormatBitString = %s, %v; want %s",
						got,
						err,
						want,
					)
				}

				back, err := per.ParseBitString(got)
				if err != nil {
					t.Fatalf(
						"ParseBitString: %v",
						err,
					)
				}

				if back.BitLength != bits || !bytes.Equal(
					back.Bytes,
					value.Bytes,
				) {
					t.Fatalf(
						"ParseBitString = %d bits % x, "+
							"want %d bits % x",
						back.BitLength,
						back.Bytes,
						bits,
						value.Bytes,
					)
				}
			},
		)
	}
}

// TestRegressionBinaryRefusesShortBytes checks a BitLength longer than the
// bytes behind it is refused, so the kernel never reads past them.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation, as TestRegressionBinaryClampsToTheBytes
//   - 2026-10-21 21:38: FormatBitString refuses the value with ErrShortBitString, where
//     BitStringToBinary cut the length to the bytes (review P31)
func TestRegressionBinaryRefusesShortBytes(t *testing.T) {
	t.Parallel()

	var (
		value = &asn1.BitString{
			Bytes:     _TextPayload(9),
			BitLength: 1000,
		}
		got, err = per.FormatBitString(value)
	)

	if got != "" || !errors.Is(
		err,
		per.ErrShortBitString,
	) {
		t.Fatalf(
			"FormatBitString = %q, %v; want \"\", ErrShortBitString",
			got,
			err,
		)
	}
}

// TestRegressionBinaryRejectsInvalid plants a character that is neither '0'
// nor '1' at every position that matters to a block kernel and checks the
// error names its index.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
//   - 2026-10-21 21:38: the error names the index of the character, not the start of its
//     eight-character group (review P31)
func TestRegressionBinaryRejectsInvalid(t *testing.T) {
	t.Parallel()

	clean, err := per.FormatBitString(_BitString(BINARY_LENGTHS))
	if err != nil {
		t.Fatal(err)
	}

	for _, at := range BINARY_INVALID_AT {
		t.Run(
			"at_"+strconv.Itoa(at),
			func(t *testing.T) {
				t.Parallel()

				text := []byte(clean)
				text[at] = '2'

				_, err := per.ParseBitString(string(text))
				if !errors.Is(
					err,
					per.ErrInvalidBinary,
				) {
					t.Fatalf(
						"got %v, want ErrInvalidBinary",
						err,
					)
				}

				want := "at index " + strconv.Itoa(at) + ":"
				if !strings.Contains(
					err.Error(),
					want,
				) {
					t.Errorf(
						"error %q does not say %q",
						err,
						want,
					)
				}
			},
		)
	}
}

// _BitString builds a value of the given bit length over the payload, with the
// bits past the length cleared, as a parsed value would have them.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func _BitString(bits int) *asn1.BitString {
	var (
		count = (bits + per.BITS_PER_BYTE - 1) / per.BITS_PER_BYTE
		data  = _TextPayload(count)
	)

	if rest := bits % per.BITS_PER_BYTE; rest != 0 {
		data[count-1] &= 0xFF << (per.BITS_PER_BYTE - rest)
	}

	return &asn1.BitString{
		Bytes:     data,
		BitLength: bits,
	}
}

// _BinaryReference renders a bit string the slow obvious way.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func _BinaryReference(value *asn1.BitString) string {
	out := make(
		[]byte,
		value.BitLength,
	)

	for idx := range out {
		var (
			shift = per.BITS_PER_BYTE - 1 - idx%per.BITS_PER_BYTE
			bit   = value.Bytes[idx/per.BITS_PER_BYTE] >> shift & 1
		)

		out[idx] = '0' + bit
	}

	return string(out)
}
