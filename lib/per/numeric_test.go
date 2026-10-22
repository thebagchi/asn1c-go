package per_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// The positions an invalid character is planted at: the first character, both
// sides of each kernel block boundary, and past the last full block.
var (
	INVALID_AT = []int{0, 15, 16, 31, 32, 33, 63, 64, 100, 129}
)

// TestRegressionNumericStringRejectsInvalidCharacter plants a character outside
// the alphabet at every position that matters to a block kernel and checks
// the error is the one the per-character path reports.
//
// Revisions:
//   - 2026-09-23 05:50: initial creation
func TestRegressionNumericStringRejectsInvalidCharacter(t *testing.T) {
	t.Parallel()

	const LENGTH = 130

	for _, item := range VARIANTS {
		for _, at := range INVALID_AT {
			t.Run(
				item.name+"/at_"+strconv.Itoa(at),
				func(t *testing.T) {
					t.Parallel()

					text := []byte(_NumericText(
						LENGTH,
						0,
					))
					text[at] = 'x'

					var (
						enc = item.encoder()

						err = enc.EncodeRestrictedString(
							string(text),
							per.STRING_NUMERIC,
							per.Unconstrained(),
						)
					)
					if !errors.Is(
						err,
						per.ErrCharacterNotInAlphabet,
					) {
						t.Fatalf(
							"got %v, want ErrCharacterNotInAlphabet",
							err,
						)
					}
				},
			)
		}
	}
}

// TestRegressionNumericStringRejectsInvalidNibble corrupts an encoded stream
// so a nibble is outside the alphabet, at every position that matters to a
// block kernel, and checks the decoder reports it.
//
// Revisions:
//   - 2026-09-23 05:50: initial creation
func TestRegressionNumericStringRejectsInvalidNibble(t *testing.T) {
	t.Parallel()

	// 130 characters is past 127, so clause 11.9.3.7 gives the unconstrained
	// length determinant two bytes, and the nibbles start after them.
	const (
		LENGTH      = 130
		DETERMINANT = 2
	)

	for _, at := range INVALID_AT {
		t.Run(
			"byte_"+strconv.Itoa(at/2),
			func(t *testing.T) {
				t.Parallel()

				// UPER, octet-aligned, unconstrained: the determinant, then the
				// nibbles, so character position at sits in byte DETERMINANT+at/2.
				var (
					enc = UPER.encoder()

					err = enc.EncodeRestrictedString(
						_NumericText(
							LENGTH,
							0,
						),
						per.STRING_NUMERIC,
						per.Unconstrained(),
					)
				)
				if err != nil {
					t.Fatal(err)
				}

				encoded := append(
					[]byte(nil),
					enc.Bytes()...,
				)
				encoded[DETERMINANT+at/2] = 0xFF

				dec := UPER.decoder(encoded)

				_, err = dec.DecodeRestrictedString(
					per.STRING_NUMERIC,
					per.Unconstrained(),
				)
				if !errors.Is(
					err,
					per.ErrCharacterNotInAlphabet,
				) {
					t.Fatalf(
						"got %v, want ErrCharacterNotInAlphabet",
						err,
					)
				}
			},
		)
	}
}
