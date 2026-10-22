package per_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// How far the differential test looks, in bytes: past several kernel blocks,
// through every tail length.
const (
	HEX_LENGTHS = 300
)

// The character positions an invalid character is planted at: the first, both
// sides of each kernel block boundary, and inside the tail.
var (
	HEX_INVALID_AT = []int{0, 1, 63, 64, 65, 127, 128, 129, 300, 599}
)

// TestRegressionHexMatchesStandardLibrary checks BytesToHex against
// encoding/hex and HexToBytes against the data, in both letter cases, at every
// length up to several blocks. It covers lib/review.md §9.4.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func TestRegressionHexMatchesStandardLibrary(t *testing.T) {
	t.Parallel()

	for size := range HEX_LENGTHS + 1 {
		t.Run(
			strconv.Itoa(size),
			func(t *testing.T) {
				t.Parallel()

				var (
					data = _TextPayload(size)
					want = hex.EncodeToString(data)
					got  = per.BytesToHex(data)
				)

				if got != want {
					t.Fatalf(
						"BytesToHex = %s, want %s",
						got,
						want,
					)
				}

				for _, text := range []string{want, strings.ToUpper(want)} {
					back, err := per.HexToBytes(text)
					if err != nil {
						t.Fatalf(
							"HexToBytes(%q): %v",
							text,
							err,
						)
					}

					if !bytes.Equal(
						back,
						data,
					) {
						t.Fatalf(
							"HexToBytes = % x, want % x",
							back,
							data,
						)
					}
				}
			},
		)
	}
}

// TestRegressionHexRejectsInvalid plants a character that is not a
// hexadecimal digit at every position that matters to a block kernel and
// checks the error names it; and checks an odd length is reported only when
// every character was good, which is encoding/hex's order.
//
// Revisions:
//   - 2026-09-23 08:50: initial creation
func TestRegressionHexRejectsInvalid(t *testing.T) {
	t.Parallel()

	clean := per.BytesToHex(_TextPayload(HEX_LENGTHS))

	for _, at := range HEX_INVALID_AT {
		t.Run(
			"at_"+strconv.Itoa(at),
			func(t *testing.T) {
				t.Parallel()

				text := []byte(clean)
				text[at] = 'g'

				_, err := per.HexToBytes(string(text))
				if !errors.Is(
					err,
					per.ErrInvalidHex,
				) {
					t.Fatalf(
						"got %v, want ErrInvalidHex",
						err,
					)
				}

				if !strings.Contains(
					err.Error(),
					"'g'",
				) {
					t.Errorf(
						"error %q does not name the character",
						err,
					)
				}
			},
		)
	}

	t.Run(
		"odd length",
		func(t *testing.T) {
			t.Parallel()

			_, err := per.HexToBytes(clean[:len(clean)-1])
			if !errors.Is(
				err,
				per.ErrOddHexLength,
			) {
				t.Fatalf(
					"got %v, want ErrOddHexLength",
					err,
				)
			}
		},
	)

	t.Run(
		"invalid before odd length",
		func(t *testing.T) {
			t.Parallel()

			text := []byte(clean[:len(clean)-1])
			text[HEX_INVALID_AT[3]] = 'g'

			if _, err := per.HexToBytes(string(text)); !errors.Is(
				err,
				per.ErrInvalidHex,
			) {
				t.Fatalf(
					"got %v, want ErrInvalidHex",
					err,
				)
			}
		},
	)
}
