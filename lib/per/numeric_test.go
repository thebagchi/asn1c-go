package per_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// GOLDEN_FILE holds the NumericString encoder's output as it was before the
// kernels existed, recorded from the previous implementation and round-tripped
// through its decoder at the time. It is the oracle for everything that came
// after: two variants, six bit offsets, twenty-four lengths straddling every
// block boundary, three constraint shapes.
const (
	GOLDEN_FILE = "testdata/numeric_golden.json"
)

// The positions an invalid character is planted at: the first character, both
// sides of each kernel block boundary, and past the last full block.
var (
	INVALID_AT = []int{0, 15, 16, 31, 32, 33, 63, 64, 100, 129}
)

// golden is one recorded case. The value is regenerated from its length and
// seed by numericText, the same function that produced it, so the file holds
// only the bytes.
type golden struct {
	Aligned    bool   `json:"aligned"`
	Offset     int    `json:"offset"`
	Length     int    `json:"length"`
	Seed       int    `json:"seed"`
	Constraint string `json:"constraint"`
	Hex        string `json:"hex"`
}

// TestRegressionNumericStringMatchesGolden encodes every recorded case and
// compares the bytes, then decodes them back. It covers lib/review.md §9.3.
//
// Bit-exactness is the whole requirement. A kernel that packed the right
// characters into the wrong nibble order, or dropped a block boundary, would
// still produce a string that decodes to something - this is what says it is
// the same stream the scalar loop produced, at every offset a preamble can
// leave the codec at.
//
// Revisions:
//   - 2026-09-23 05:50: initial creation
func TestRegressionNumericStringMatchesGolden(t *testing.T) {
	t.Parallel()

	for _, item := range loadGolden(t) {
		t.Run(goldenName(item), func(t *testing.T) {
			t.Parallel()

			var (
				value = numericText(item.Length, item.Seed)
				size  = goldenConstraint(item)
				enc   = variantOf(item).encoder()
			)

			for range item.Offset {
				if err := enc.EncodeBoolean(true); err != nil {
					t.Fatal(err)
				}
			}

			err := enc.EncodeRestrictedString(value, per.STRING_NUMERIC, size)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			if got := hex.EncodeToString(enc.Bytes()); got != item.Hex {
				t.Fatalf("encoded %s, golden %s", got, item.Hex)
			}

			dec := variantOf(item).decoder(enc.Bytes())

			for range item.Offset {
				if _, err := dec.DecodeBoolean(); err != nil {
					t.Fatal(err)
				}
			}

			got, err := dec.DecodeRestrictedString(per.STRING_NUMERIC, size)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			if got != value {
				t.Fatalf("decoded %q, want %q", got, value)
			}
		})
	}
}

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
			t.Run(item.name+"/at_"+strconv.Itoa(at), func(t *testing.T) {
				t.Parallel()

				text := []byte(numericText(LENGTH, 0))
				text[at] = 'x'

				enc := item.encoder()

				err := enc.EncodeRestrictedString(
					string(text),
					per.STRING_NUMERIC,
					per.Unconstrained(),
				)
				if !errors.Is(err, per.ErrCharacterNotInAlphabet) {
					t.Fatalf("got %v, want ErrCharacterNotInAlphabet", err)
				}
			})
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
		t.Run("byte_"+strconv.Itoa(at/2), func(t *testing.T) {
			t.Parallel()

			// UPER, octet-aligned, unconstrained: the determinant, then the
			// nibbles, so character position at sits in byte DETERMINANT+at/2.
			enc := UPER.encoder()

			err := enc.EncodeRestrictedString(
				numericText(LENGTH, 0),
				per.STRING_NUMERIC,
				per.Unconstrained(),
			)
			if err != nil {
				t.Fatal(err)
			}

			encoded := append([]byte(nil), enc.Bytes()...)
			encoded[DETERMINANT+at/2] = 0xFF

			dec := UPER.decoder(encoded)

			_, err = dec.DecodeRestrictedString(
				per.STRING_NUMERIC,
				per.Unconstrained(),
			)
			if !errors.Is(err, per.ErrCharacterNotInAlphabet) {
				t.Fatalf("got %v, want ErrCharacterNotInAlphabet", err)
			}
		})
	}
}

// loadGolden reads the recorded cases.
//
// Revisions:
//   - 2026-09-23 05:50: initial creation
func loadGolden(t *testing.T) []*golden {
	t.Helper()

	raw, err := os.ReadFile(GOLDEN_FILE)
	if err != nil {
		t.Fatalf("read %s: %v", GOLDEN_FILE, err)
	}

	var (
		cases []*golden
	)

	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse %s: %v", GOLDEN_FILE, err)
	}

	if len(cases) == 0 {
		t.Fatalf("%s holds no cases", GOLDEN_FILE)
	}

	return cases
}

// goldenName names one case for the test output.
//
// Revisions:
//   - 2026-09-23 05:50: initial creation
func goldenName(item *golden) string {
	return variantOf(item).name +
		"/offset_" + strconv.Itoa(item.Offset) +
		"/len_" + strconv.Itoa(item.Length) +
		"/" + item.Constraint
}

// variantOf returns the variant a case was recorded in.
//
// Revisions:
//   - 2026-09-23 07:05: initial creation
func variantOf(item *golden) *variant {
	if item.Aligned {
		return APER
	}

	return UPER
}

// goldenConstraint rebuilds the constraint a case was recorded under.
//
// Revisions:
//   - 2026-09-23 05:50: initial creation
func goldenConstraint(item *golden) *per.Constraint {
	const RANGE_SLACK = 7

	switch item.Constraint {
	case "fixed":
		return per.Constrained(int64(item.Length), int64(item.Length))
	case "range":
		return per.Constrained(0, int64(item.Length+RANGE_SLACK))
	default:
		return per.Unconstrained()
	}
}
