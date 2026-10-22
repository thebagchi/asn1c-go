//go:build amd64

package per

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
)

// This file is an internal test because the range kernels are unexported, and amd64 only
// because they are assembly.

// RANGE_TEST_BLOCKS is how many blocks of each kernel a text spans at most: a text runs
// from empty to this many blocks and one byte past it.
const (
	RANGE_TEST_BLOCKS = 3
)

// _RangeKernel is one range kernel under test, with its block.
type _RangeKernel struct {
	name  string
	have  bool
	block int
	check func(
		src []byte,
		lower,
		upper byte,
	) int
}

// TestRegression_P28RangeKernels guards review P28: each kernel returns the bytes of the
// whole blocks before the first block with a byte outside lower..upper. It must stop
// before that block, so the Go check that follows still finds the byte and reports it.
// Every byte value goes at every place, for IA5String and for VisibleString.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation (review P28)
//   - 2026-10-21 23:53: the AVX-512 kernel, which skips unless cpu.HAS_AVX512 (review P33)
func TestRegression_P28RangeKernels(t *testing.T) {
	var (
		kernels = []*_RangeKernel{
			{
				name:  NAME_SSE2,
				have:  true,
				block: RANGE_SSE2_BYTES,
				check: _CheckRangeSSE2,
			},
			{
				name:  NAME_AVX2,
				have:  cpu.HAS_AVX2,
				block: RANGE_AVX2_BYTES,
				check: _CheckRangeAVX2,
			},
			{
				name:  NAME_AVX512,
				have:  cpu.HAS_AVX512,
				block: RANGE_AVX512_BYTES,
				check: _CheckRangeAVX512,
			},
		}
		kinds = map[string]StringKind{
			"ia5":     STRING_IA5,
			"visible": STRING_VISIBLE,
		}
	)

	for _, kernel := range kernels {
		for name, kind := range kinds {
			alphabet := ALPHABET_UNALIGNED[kind]

			t.Run(
				kernel.name+"/"+name,
				func(t *testing.T) {
					if !kernel.have {
						t.Skipf(
							"%s is not supported on this processor",
							kernel.name,
						)
					}

					_CheckKernelBytes(
						t,
						kernel,
						alphabet,
					)
				},
			)
		}
	}
}

// _CheckKernelBytes runs one kernel on clean texts of every length, and on texts with
// each byte value at each place.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation
func _CheckKernelBytes(
	t *testing.T,
	kernel *_RangeKernel,
	alphabet *_Alphabet,
) {
	t.Helper()

	longest := RANGE_TEST_BLOCKS*kernel.block + 1
	for size := range longest + 1 {
		_CheckKernelText(
			t,
			kernel,
			alphabet,
			_RangeText(size),
		)

		for place := range size {
			for value := range CHECK_BYTE_VALUES {
				text := _RangeText(size)
				text[place] = byte(value)

				_CheckKernelText(
					t,
					kernel,
					alphabet,
					text,
				)
			}
		}
	}
}

// _CheckKernelText compares one kernel call with the blocks a byte loop finds clean.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation
func _CheckKernelText(
	t *testing.T,
	kernel *_RangeKernel,
	alphabet *_Alphabet,
	text []byte,
) {
	t.Helper()

	clean := len(text)
	for idx, char := range text {
		if rune(char) < alphabet.lower || rune(char) > alphabet.upper {
			clean = idx

			break
		}
	}

	var (
		want = clean / kernel.block * kernel.block

		got = kernel.check(
			text,
			byte(alphabet.lower),
			byte(alphabet.upper),
		)
	)
	if got != want {
		t.Fatalf(
			"%s %x..%x text %x: checked %d, want %d",
			kernel.name,
			alphabet.lower,
			alphabet.upper,
			text,
			got,
			want,
		)
	}
}

// _RangeText is size bytes of 'A', which every range alphabet holds.
//
// Revisions:
//   - 2026-10-21 16:08: initial creation
func _RangeText(size int) []byte {
	text := make(
		[]byte,
		size,
	)
	for idx := range text {
		text[idx] = 'A'
	}

	return text
}
