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

// TestRegressionBinaryMatchesReference checks BitStringToBinary against the
// bit loop and BitStringFromBinary against the bytes, at every bit length up
// to several blocks, including the lengths that end inside a byte. It covers
// lib/review.md §9.4.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func TestRegressionBinaryMatchesReference(t *testing.T) {
	t.Parallel()

	for bits := range BINARY_LENGTHS + 1 {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			t.Parallel()

			var (
				value = bitString(bits)
				want  = binaryReference(value)
				got   = per.BitStringToBinary(value)
			)

			if got != want {
				t.Fatalf("BitStringToBinary = %s, want %s", got, want)
			}

			back, err := per.BitStringFromBinary(got)
			if err != nil {
				t.Fatalf("BitStringFromBinary: %v", err)
			}

			if back.BitLength != bits || !bytes.Equal(back.Bytes, value.Bytes) {
				t.Fatalf(
					"BitStringFromBinary = %d bits % x, want %d bits % x",
					back.BitLength,
					back.Bytes,
					bits,
					value.Bytes,
				)
			}
		})
	}
}

// TestRegressionBinaryClampsToTheBytes checks a BitLength longer than the
// bytes behind it is cut to them, which the kernel must not read past.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func TestRegressionBinaryClampsToTheBytes(t *testing.T) {
	t.Parallel()

	var (
		value = &asn1.BitString{Bytes: textPayload(9), BitLength: 1000}
		whole = &asn1.BitString{Bytes: textPayload(9), BitLength: 72}
	)

	if got, want := per.BitStringToBinary(value), binaryReference(whole); got != want {
		t.Fatalf("BitStringToBinary = %s, want %s", got, want)
	}
}

// TestRegressionBinaryRejectsInvalid plants a character that is neither '0'
// nor '1' at every position that matters to a block kernel and checks the
// error names the eight-character group holding it, as it always has.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func TestRegressionBinaryRejectsInvalid(t *testing.T) {
	t.Parallel()

	clean := per.BitStringToBinary(bitString(BINARY_LENGTHS))

	for _, at := range BINARY_INVALID_AT {
		t.Run("at_"+strconv.Itoa(at), func(t *testing.T) {
			t.Parallel()

			text := []byte(clean)
			text[at] = '2'

			_, err := per.BitStringFromBinary(string(text))
			if !errors.Is(err, per.ErrInvalidBinary) {
				t.Fatalf("got %v, want ErrInvalidBinary", err)
			}

			want := "at offset " + strconv.Itoa(at-at%per.BITS_PER_BYTE) + ":"
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not say %q", err, want)
			}
		})
	}
}

// bitString builds a value of the given bit length over the payload, with the
// bits past the length cleared, as a parsed value would have them.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func bitString(bits int) *asn1.BitString {
	var (
		count = (bits + per.BITS_PER_BYTE - 1) / per.BITS_PER_BYTE
		data  = textPayload(count)
	)

	if rest := bits % per.BITS_PER_BYTE; rest != 0 {
		data[count-1] &= 0xFF << (per.BITS_PER_BYTE - rest)
	}

	return &asn1.BitString{Bytes: data, BitLength: bits}
}

// binaryReference renders a bit string the slow obvious way.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func binaryReference(value *asn1.BitString) string {
	out := make([]byte, value.BitLength)

	for idx := range out {
		var (
			shift = per.BITS_PER_BYTE - 1 - idx%per.BITS_PER_BYTE
			bit   = value.Bytes[idx/per.BITS_PER_BYTE] >> shift & 1
		)

		out[idx] = '0' + bit
	}

	return string(out)
}
