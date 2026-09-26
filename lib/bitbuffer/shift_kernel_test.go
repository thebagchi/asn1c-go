package bitbuffer_test

import (
	"bytes"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
	"github.com/thebagchi/asn1c-go/lib/cpu"
)

// How many blocks each kernel is run over. One block is the minimum, two puts
// a block boundary inside the buffer, and five is not a power of two.
var (
	KERNEL_BLOCKS = []int{1, 2, 5}
)

// TestRegressionEveryKernelMatchesScalar runs every kernel this machine
// supports against the plain byte loop, at every shift amount, in both
// directions. It covers lib/review.md §9.1.
//
// The round-trip tests elsewhere in this package only ever exercise the kernel
// that was selected at start-up, so on a machine with AVX2 the SSE2 kernel
// would otherwise never run, and a defect in it would surface only on the
// machine that lacks AVX2 - which is exactly the machine nobody tests on. The
// Go kernel is in the same table, so on an architecture without assembly this
// test still has something to say.
//
// Revisions:
//   - 2026-09-23 04:02: initial creation
//   - 2026-09-24 01:40: portable, with the Go kernel a table entry
func TestRegressionEveryKernelMatchesScalar(t *testing.T) {
	for _, kernel := range bitbuffer.SHIFT_KERNELS {
		t.Run(kernel.Name(), func(t *testing.T) {
			if !kernel.Have() {
				t.Skipf("%s is not supported on this processor", kernel.Name())
			}

			for _, blocks := range KERNEL_BLOCKS {
				checkKernel(t, kernel, blocks*kernel.Block())
			}
		})
	}
}

// TestSelectedKernelIsTheWidestSupported pins the policy _Select implements,
// and that the table always opens with the Go kernel.
//
// Revisions:
//   - 2026-09-23 04:02: initial creation
//   - 2026-09-24 01:40: checks the Go kernel leads the table
func TestSelectedKernelIsTheWidestSupported(t *testing.T) {
	first := bitbuffer.SHIFT_KERNELS[0]
	if first.Name() != bitbuffer.NAME_GO || !first.Have() {
		t.Errorf("the table opens with %s, want the Go kernel", first.Name())
	}

	var (
		widest string
	)

	for _, kernel := range bitbuffer.SHIFT_KERNELS {
		if kernel.Have() {
			widest = kernel.Name()
		}
	}

	if got := bitbuffer.SHIFT_KERNEL.Name(); got != widest {
		t.Errorf("selected %s, widest supported is %s", got, widest)
	}

	t.Logf(
		"selected shift kernel: %s (processor: %s)",
		bitbuffer.SHIFT_KERNEL.Name(),
		cpu.Vector(),
	)
}

// checkKernel compares one kernel with the byte loop over one buffer size, at
// every shift, with the shift amounts each way round - as the write path and
// the read path pass them.
//
// Revisions:
//   - 2026-09-23 04:02: initial creation
func checkKernel(t *testing.T, kernel interface {
	Name() string
	Run(dst, src []byte, left, right uint8)
}, size int) {
	t.Helper()

	src := payload(size + 1)

	for left := uint8(1); left < bitbuffer.BITS_PER_BYTE; left++ {
		var (
			right = bitbuffer.BITS_PER_BYTE - left
			got   = make([]byte, size)
			want  = shiftedReference(src, size, left, right)
		)

		kernel.Run(got, src, left, right)

		if !bytes.Equal(got, want) {
			t.Fatalf(
				"%s: len %d, <<%d >>%d: got % x, want % x",
				kernel.Name(),
				size,
				left,
				right,
				got,
				want,
			)
		}
	}
}

// shiftedReference is the kernel's contract written the slow obvious way.
//
// Revisions:
//   - 2026-09-23 04:02: initial creation
func shiftedReference(src []byte, size int, left, right uint8) []byte {
	out := make([]byte, size)

	for idx := range out {
		out[idx] = src[idx]<<left | src[idx+1]>>right
	}

	return out
}
