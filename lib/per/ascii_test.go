package per_test

import (
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// The known-multiplier types whose alphabets are entirely ASCII, and so take
// the byte path, and two whose alphabets are not, and so must still count
// runes.
var (
	ASCII_KINDS = []struct {
		name string
		kind per.StringKind
	}{
		{
			name: "ia5",
			kind: per.STRING_IA5,
		},
		{
			name: "visible",
			kind: per.STRING_VISIBLE,
		},
		{
			name: "printable",
			kind: per.STRING_PRINTABLE,
		},
		{
			name: "numeric",
			kind: per.STRING_NUMERIC,
		},
	}
	WIDE_KINDS = []struct {
		name string
		kind per.StringKind
	}{
		{
			name: "utf8",
			kind: per.STRING_UTF8,
		},
		{
			name: "bmp",
			kind: per.STRING_BMP,
		},
	}
)

// A value with one character outside ASCII, whose byte length and rune count
// differ - the case that separates counting bytes from counting runes.
const (
	ACCENTED = "12é3"
)

// TestRegressionNonASCIIIsRejectedByASCIIAlphabets checks that a string with a
// character outside ASCII is refused by every ASCII alphabet, in both
// variants. It covers lib/review.md §9.3.
//
// The byte path is taken only when a string's byte length equals its rune
// count, which is exactly when it is pure ASCII; this is the other side of that
// test - a string that is not must still reach the per-rune path and be
// reported there.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func TestRegressionNonASCIIIsRejectedByASCIIAlphabets(t *testing.T) {
	t.Parallel()

	for _, item := range VARIANTS {
		for _, kind := range ASCII_KINDS {
			t.Run(
				item.name+"/"+kind.name,
				func(t *testing.T) {
					t.Parallel()

					var (
						enc = item.encoder()

						err = enc.EncodeRestrictedString(
							ACCENTED,
							kind.kind,
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

// TestRegressionWideAlphabetsStillCountRunes round-trips a non-ASCII string
// through the types whose alphabets hold it, so the character count that
// sizes the length determinant is shown to be runes rather than bytes.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func TestRegressionWideAlphabetsStillCountRunes(t *testing.T) {
	t.Parallel()

	for _, item := range VARIANTS {
		for _, kind := range WIDE_KINDS {
			t.Run(
				item.name+"/"+kind.name,
				func(t *testing.T) {
					t.Parallel()

					var (
						enc = item.encoder()

						err = enc.EncodeRestrictedString(
							ACCENTED,
							kind.kind,
							per.Unconstrained(),
						)
					)
					if err != nil {
						t.Fatalf(
							"encode: %v",
							err,
						)
					}

					got, err := item.decoder(
						enc.Bytes(),
					).DecodeRestrictedString(
						kind.kind,
						per.Unconstrained(),
					)
					if err != nil {
						t.Fatalf(
							"decode: %v",
							err,
						)
					}

					if got != ACCENTED {
						t.Fatalf(
							"decoded %q, want %q",
							got,
							ACCENTED,
						)
					}
				},
			)
		}
	}
}
