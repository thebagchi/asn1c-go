package per_test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
	"github.com/thebagchi/asn1c-go/lib/per"
)

// The alphabet the kernels implement, in the order clause 30.4.4 numbers it.
const (
	NUMERIC_ALPHABET = " 0123456789"
)

// How many blocks each kernel is run over: one, two (a boundary inside the
// buffer), and five (not a power of two).
var (
	NUMERIC_BLOCKS = []int{1, 2, 5}
)

// TestRegressionNumericKernelsMatchScalar drives every kernel in the table,
// the Go one included, against the obvious byte loop in both directions, on
// valid input and with an invalid character at every position of two blocks.
// It covers lib/review.md §9.3.
//
// The invalid cases check two things the golden vectors cannot: that a kernel
// stops before the block holding the bad character rather than after it, and
// that everything it did write before stopping is right. A kernel that
// consumed the bad block and returned would leave the scalar loop nothing to
// report, and the string would encode as though the character were valid.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
//   - 2026-09-24 01:40: portable, over a table that includes the Go kernel
func TestRegressionNumericKernelsMatchScalar(t *testing.T) {
	t.Parallel()

	for _, kernel := range per.NUMERIC_KERNELS {
		t.Run(kernel.Name(), func(t *testing.T) {
			t.Parallel()

			if !kernel.Have() {
				t.Skipf("%s is not supported on this processor", kernel.Name())
			}

			for _, blocks := range NUMERIC_BLOCKS {
				checkPack(t, kernel, blocks*kernel.EncodeBlock())
				checkUnpack(t, kernel, blocks*kernel.DecodeBlock())
			}

			checkPackStops(t, kernel)
			checkUnpackStops(t, kernel)
		})
	}
}

// TestSelectedNumericKernelIsTheWidestSupported pins the selection policy, and
// that the table always opens with the Go kernel.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
//   - 2026-09-24 01:40: checks the Go kernel leads the table
func TestSelectedNumericKernelIsTheWidestSupported(t *testing.T) {
	t.Parallel()

	checkTable(t, per.NUMERIC_KERNELS, per.NUMERIC_KERNEL)
	t.Logf(
		"selected NumericString kernel: %s (processor: %s)",
		per.NUMERIC_KERNEL.Name(),
		cpu.Vector(),
	)
}

// checkPack compares a kernel's packing with the byte loop over one length.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
func checkPack(t *testing.T, kernel textKernel, chars int) {
	t.Helper()

	var (
		text = []byte(numericText(chars, chars))
		got  = make([]byte, chars/2)
		want = packReference(text)
	)

	if done := kernel.Encode(got, text); done != chars {
		t.Fatalf("%s: pack consumed %d of %d valid characters", kernel.Name(), done, chars)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("%s: pack %d: got % x, want % x", kernel.Name(), chars, got, want)
	}
}

// checkUnpack compares a kernel's unpacking with the byte loop over one length.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
func checkUnpack(t *testing.T, kernel textKernel, pairs int) {
	t.Helper()

	var (
		want   = []byte(numericText(pairs*2, pairs))
		packed = packReference(want)
		got    = make([]byte, pairs*2)
	)

	if done := kernel.Decode(got, packed); done != pairs {
		t.Fatalf("%s: unpack consumed %d of %d valid bytes", kernel.Name(), done, pairs)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("%s: unpack %d: got %q, want %q", kernel.Name(), pairs, got, want)
	}
}

// checkPackStops plants an invalid character at every position of two blocks
// and checks the kernel stops at that block with everything before it right.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
//   - 2026-09-24 01:40: in terms of the kernel's block, so the Go kernel's
//     pair is a block like any other
func checkPackStops(t *testing.T, kernel textKernel) {
	t.Helper()

	var (
		block = kernel.EncodeBlock()
		chars = 2 * block
		clean = []byte(numericText(chars, 0))
	)

	for at := range chars {
		text := append([]byte(nil), clean...)
		text[at] = 'x'

		var (
			got  = make([]byte, chars/2)
			want = at / block * block
		)

		if done := kernel.Encode(got, text); done != want {
			t.Fatalf(
				"%s: invalid at %d: consumed %d, want %d",
				kernel.Name(),
				at,
				done,
				want,
			)
		}

		if !bytes.Equal(got[:want/2], packReference(clean[:want])) {
			t.Fatalf("%s: invalid at %d: bytes before it are wrong", kernel.Name(), at)
		}
	}
}

// checkUnpackStops plants an invalid nibble at every position of two blocks
// and checks the kernel stops at that block with everything before it right.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
//   - 2026-09-24 01:40: in terms of the kernel's block
func checkUnpackStops(t *testing.T, kernel textKernel) {
	t.Helper()

	var (
		block = kernel.DecodeBlock()
		pairs = 2 * block
		text  = []byte(numericText(pairs*2, 0))
		clean = packReference(text)
	)

	for at := range pairs * 2 {
		packed := append([]byte(nil), clean...)
		packed[at/2] |= 0x0F << (4 * uint(1-at%2))

		var (
			got  = make([]byte, pairs*2)
			want = at / 2 / block * block
		)

		if done := kernel.Decode(got, packed); done != want {
			t.Fatalf(
				"%s: bad nibble at %d: consumed %d, want %d",
				kernel.Name(),
				at,
				done,
				want,
			)
		}

		if !bytes.Equal(got[:want*2], text[:want*2]) {
			t.Fatalf(
				"%s: bad nibble at %d: characters before it are wrong",
				kernel.Name(),
				at,
			)
		}
	}
}

// checkTable checks a kernel table's two invariants: the Go kernel leads it
// and can always run, and the selected kernel is the widest that can. It is
// generic because the tables hold an unexported type, which a test can hold
// values of but not name.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func checkTable[K textKernel](t *testing.T, kernels []K, selected K) {
	t.Helper()

	if first := kernels[0]; first.Name() != per.NAME_GO || !first.Have() {
		t.Errorf("the table opens with %s, want the Go kernel", first.Name())
	}

	var (
		widest string
	)

	for _, kernel := range kernels {
		if kernel.Have() {
			widest = kernel.Name()
		}
	}

	if got := selected.Name(); got != widest {
		t.Errorf("selected %s, widest supported is %s", got, widest)
	}
}

// packReference is the kernels' contract written the slow obvious way: each
// character's position in the alphabet, two to a byte, the first in the high
// nibble.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
func packReference(text []byte) []byte {
	out := make([]byte, len(text)/2)

	for idx := range out {
		var (
			high = byte(alphabetIndex(text[2*idx]))
			low  = byte(alphabetIndex(text[2*idx+1]))
		)

		out[idx] = high<<4 | low
	}

	return out
}

// alphabetIndex is a character's number in the alphabet.
//
// Revisions:
//   - 2026-09-23 05:52: initial creation
func alphabetIndex(char byte) int {
	for idx := range len(NUMERIC_ALPHABET) {
		if NUMERIC_ALPHABET[idx] == char {
			return idx
		}
	}

	panic("character " + strconv.Quote(string(char)) + " is not in the alphabet")
}

// textKernel is what the checks need from a kernel of any family.
type textKernel interface {
	Name() string
	Have() bool
	EncodeBlock() int
	DecodeBlock() int
	Encode(dst, src []byte) int
	Decode(dst, src []byte) int
}
