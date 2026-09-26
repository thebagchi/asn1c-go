package per_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
	"github.com/thebagchi/asn1c-go/lib/per"
)

// How many blocks each kernel is run over: one, two (a boundary inside the
// buffer), and five (not a power of two).
var (
	HEX_BLOCKS = []int{1, 2, 5}
)

// TestRegressionHexKernelsMatchStandardLibrary drives every kernel in the
// table, the Go one included, against encoding/hex in both directions and
// both letter cases, and checks each stops before a block holding a character
// that is not a hexadecimal digit. It covers lib/review.md §9.4.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func TestRegressionHexKernelsMatchStandardLibrary(t *testing.T) {
	t.Parallel()

	for _, kernel := range per.HEX_KERNELS {
		t.Run(kernel.Name(), func(t *testing.T) {
			t.Parallel()

			if !kernel.Have() {
				t.Skipf("%s is not supported on this processor", kernel.Name())
			}

			for _, blocks := range HEX_BLOCKS {
				checkHexEncode(t, kernel, blocks*kernel.EncodeBlock())
				checkHexDecode(t, kernel, blocks*kernel.DecodeBlock())
			}

			checkHexStops(t, kernel)
		})
	}
}

// TestSelectedHexKernelIsTheWidestSupported pins the selection policy.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func TestSelectedHexKernelIsTheWidestSupported(t *testing.T) {
	t.Parallel()

	checkTable(t, per.HEX_KERNELS, per.HEX_KERNEL)
	t.Logf(
		"selected hex kernel: %s (processor: %s)",
		per.HEX_KERNEL.Name(),
		cpu.Vector(),
	)
}

// checkHexEncode compares a kernel's rendering with encoding/hex over one
// length.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func checkHexEncode(t *testing.T, kernel textKernel, size int) {
	t.Helper()

	var (
		data = textPayload(size)
		got  = make([]byte, 2*size)
		want = hex.EncodeToString(data)
	)

	if done := kernel.Encode(got, data); done != size {
		t.Fatalf("%s: encode consumed %d of %d bytes", kernel.Name(), done, size)
	}

	if string(got) != want {
		t.Fatalf("%s: encode %d: got %s, want %s", kernel.Name(), size, got, want)
	}
}

// checkHexDecode compares a kernel's parse with the data over one length in
// characters, in both letter cases.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 01:40: takes the length in characters, the unit the kernel's
//     block is in
func checkHexDecode(t *testing.T, kernel textKernel, chars int) {
	t.Helper()

	var (
		want = textPayload(chars / per.HEX_PAIR)
		text = hex.EncodeToString(want)
	)

	for _, variant := range []string{text, strings.ToUpper(text)} {
		got := make([]byte, len(want))

		if done := kernel.Decode(got, []byte(variant)); done != chars {
			t.Fatalf(
				"%s: decode consumed %d of %d characters",
				kernel.Name(),
				done,
				chars,
			)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf(
				"%s: decode %q: got % x, want % x",
				kernel.Name(),
				variant,
				got,
				want,
			)
		}
	}
}

// checkHexStops plants a character that is not a hexadecimal digit at every
// position of two blocks and checks the kernel stops at that block with
// everything before it right.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func checkHexStops(t *testing.T, kernel textKernel) {
	t.Helper()

	var (
		block = kernel.DecodeBlock()
		chars = 2 * block
		data  = textPayload(chars / 2)
		clean = hex.EncodeToString(data)
	)

	for at := range chars {
		text := []byte(clean)
		text[at] = 'g'

		var (
			got  = make([]byte, chars/2)
			want = at / block * block
		)

		if done := kernel.Decode(got, text); done != want {
			t.Fatalf(
				"%s: invalid at %d: consumed %d, want %d",
				kernel.Name(),
				at,
				done,
				want,
			)
		}

		if !bytes.Equal(got[:want/2], data[:want/2]) {
			t.Fatalf("%s: invalid at %d: bytes before it are wrong", kernel.Name(), at)
		}
	}
}
