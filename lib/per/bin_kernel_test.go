package per_test

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
	"github.com/thebagchi/asn1c-go/lib/per"
)

// How many blocks each kernel is run over: one, two (a boundary inside the
// buffer), and five (not a power of two).
var (
	BIN_BLOCKS = []int{1, 2, 5}
)

// TestRegressionBinaryKernelsMatchReference drives every kernel in the table,
// the Go one included, against the bit loop in both directions, and checks
// each stops before a block holding a character that is neither '0' nor '1'.
// It covers lib/review.md §9.4.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func TestRegressionBinaryKernelsMatchReference(t *testing.T) {
	t.Parallel()

	for _, kernel := range per.BIN_KERNELS {
		t.Run(
			kernel.Name(),
			func(t *testing.T) {
				t.Parallel()

				if !kernel.Have() {
					t.Skipf(
						"%s is not supported on this processor",
						kernel.Name(),
					)
				}

				for _, blocks := range BIN_BLOCKS {
					_CheckBinaryEncode(
						t,
						kernel,
						blocks*kernel.EncodeBlock(),
					)
					_CheckBinaryDecode(
						t,
						kernel,
						blocks*kernel.DecodeBlock(),
					)
				}

				_CheckBinaryStops(
					t,
					kernel,
				)
			},
		)
	}
}

// TestSelectedBinaryKernelIsTheWidestSupported pins the selection policy.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func TestSelectedBinaryKernelIsTheWidestSupported(t *testing.T) {
	t.Parallel()

	_CheckTable(
		t,
		per.BIN_KERNELS,
		per.BIN_KERNEL,
	)
	t.Logf(
		"selected binary kernel: %s (processor: %s)",
		per.BIN_KERNEL.Name(),
		cpu.Vector(),
	)
}

// _CheckBinaryEncode compares a kernel's rendering with the bit loop over one
// length in bytes.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _CheckBinaryEncode(
	t *testing.T,
	kernel _TextKernel,
	size int,
) {
	t.Helper()

	var (
		data  = _TextPayload(size)
		chars = size * per.BITS_PER_BYTE
		got   = make(
			[]byte,
			chars,
		)
		want = _BinaryReference(&asn1.BitString{
			Bytes:     data,
			BitLength: chars,
		})
	)

	if done := kernel.Encode(
		got,
		data,
	); done != size {
		t.Fatalf(
			"%s: encode consumed %d of %d bytes",
			kernel.Name(),
			done,
			size,
		)
	}

	if string(got) != want {
		t.Fatalf(
			"%s: encode %d: got %s, want %s",
			kernel.Name(),
			size,
			got,
			want,
		)
	}
}

// _CheckBinaryDecode compares a kernel's parse with the bytes over one length
// in characters.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
//   - 2026-09-24 01:40: takes the length in characters, the unit the kernel's
//     block is in
func _CheckBinaryDecode(
	t *testing.T,
	kernel _TextKernel,
	chars int,
) {
	t.Helper()

	var (
		want = _TextPayload(chars / per.BITS_PER_BYTE)
		text = _BinaryReference(&asn1.BitString{
			Bytes:     want,
			BitLength: chars,
		})
		got = make(
			[]byte,
			len(want),
		)
	)

	if done := kernel.Decode(
		got,
		[]byte(text),
	); done != chars {
		t.Fatalf(
			"%s: decode consumed %d of %d characters",
			kernel.Name(),
			done,
			chars,
		)
	}

	if !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"%s: decode %d: got % x, want % x",
			kernel.Name(),
			chars,
			got,
			want,
		)
	}
}

// _CheckBinaryStops plants a character that is neither '0' nor '1' at every
// position of two blocks and checks the kernel stops at that block with
// everything before it right.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func _CheckBinaryStops(
	t *testing.T,
	kernel _TextKernel,
) {
	t.Helper()

	var (
		block = kernel.DecodeBlock()
		chars = 2 * block
		data  = _TextPayload(chars / per.BITS_PER_BYTE)
		clean = _BinaryReference(&asn1.BitString{
			Bytes:     data,
			BitLength: chars,
		})
	)

	for at := range chars {
		text := []byte(clean)
		text[at] = '2'

		var (
			got = make(
				[]byte,
				chars/per.BITS_PER_BYTE,
			)
			want = at / block * block
		)

		if done := kernel.Decode(
			got,
			text,
		); done != want {
			t.Fatalf(
				"%s: invalid at %d: consumed %d, want %d",
				kernel.Name(),
				at,
				done,
				want,
			)
		}

		if prefix := want / per.BITS_PER_BYTE; !bytes.Equal(
			got[:prefix],
			data[:prefix],
		) {
			t.Fatalf(
				"%s: invalid at %d: bytes before it are wrong",
				kernel.Name(),
				at,
			)
		}
	}
}
