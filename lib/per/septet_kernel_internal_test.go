//go:build amd64

package per

import (
	"bytes"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
)

// This file is an internal test because the septet kernels are unexported, and amd64 only
// because they are assembly.

// SEPTET_TEST_SHORT is the longest of the lengths 0 to SEPTET_TEST_SHORT; SEPTET_TEST_LONG
// adds each side of a 64-character chunk and tails that are not a multiple of eight.
// SEPTET_TEST_ROOM is the octets past the output the buffers keep. SEPTET_TEST_STRIDE and
// SEPTET_TEST_SEED make a text that uses every bit of a character.
const (
	SEPTET_TEST_SHORT  = 33
	SEPTET_TEST_ROOM   = 4
	SEPTET_TEST_STRIDE = 37
	SEPTET_TEST_SEED   = 11
	SEPTET_TEST_TOP    = 0x7F
	SEPTET_TEST_GUARD  = 0xA5
)

var (
	SEPTET_TEST_LONG = []int{
		37,
		45,
		63,
		64,
		65,
		99,
		127,
		128,
		129,
		191,
		192,
		200,
	}
)

// _SeptetKernel is one septet kernel under test, with its block in characters.
type _SeptetKernel struct {
	name  string
	have  bool
	block int
	run   func(
		dst,
		src []byte,
	) int
}

// TestRegression_P32SeptetKernels guards review P32: each pack kernel writes the octets
// the shift writes, and each spread kernel gives the characters back, for whole blocks; a
// text shorter than a block is left alone. The oracle is the shift, _PackSeptetsShift.
//
// Revisions:
//   - 2026-10-21 22:07: initial creation (review P32)
func TestRegression_P32SeptetKernels(t *testing.T) {
	var (
		packs = []*_SeptetKernel{
			{
				name:  NAME_SSE2,
				have:  true,
				block: SEPTET_SSE2_CHARS,
				run:   _PackSeptetsSSE2,
			},
			{
				name:  NAME_AVX2,
				have:  cpu.HAS_AVX2,
				block: SEPTET_AVX2_CHARS,
				run:   _PackSeptetsAVX2,
			},
			{
				name:  NAME_AVX512,
				have:  cpu.HAS_AVX512,
				block: SEPTET_AVX512_CHARS,
				run:   _PackSeptetsAVX512,
			},
		}
		spreads = []*_SeptetKernel{
			{
				name:  NAME_SSE2,
				have:  true,
				block: SEPTET_SSE2_CHARS,
				run:   _SpreadSeptetsSSE2,
			},
			{
				name:  NAME_AVX2,
				have:  cpu.HAS_AVX2,
				block: SEPTET_AVX2_CHARS,
				run:   _SpreadSeptetsAVX2,
			},
			{
				name:  NAME_AVX512,
				have:  cpu.HAS_AVX512,
				block: SEPTET_AVX512_CHARS,
				run:   _SpreadSeptetsAVX512,
			},
		}
	)

	for idx := range packs {
		t.Run(
			packs[idx].name,
			func(t *testing.T) {
				if !packs[idx].have {
					t.Skipf(
						"%s is not supported on this processor",
						packs[idx].name,
					)
				}

				for _, size := range _SeptetSizes() {
					for _, text := range _SeptetTexts(size) {
						_CheckSeptetKernels(
							t,
							packs[idx],
							spreads[idx],
							text,
						)
					}
				}
			},
		)
	}
}

// TestRegression_P32SeptetRoom guards review P32: the kernels store one or two octets past
// the output of a block, so _PackSeptets may run a block only when those stores stay
// inside dst. Each text is packed into a window of exactly the octets it needs, cut from a
// longer buffer of guard octets, and nothing after the window may change.
//
// Revisions:
//   - 2026-10-21 22:07: initial creation (review P32)
func TestRegression_P32SeptetRoom(t *testing.T) {
	for _, size := range _SeptetSizes() {
		for _, text := range _SeptetTexts(size) {
			var (
				need = (len(text)*SEPTET_BITS + BITS_PER_BYTE - 1) / BITS_PER_BYTE
				buf  = bytes.Repeat(
					[]byte{
						SEPTET_TEST_GUARD,
					},
					need+SEPTET_TEST_ROOM,
				)
				want = make(
					[]byte,
					need,
				)
			)

			_PackSeptetsShift(
				want,
				text,
			)

			var (
				filled = _PackSeptets(
					buf[:need:need],
					text,
				)
				intact = bytes.Count(
					buf[need:],
					[]byte{
						SEPTET_TEST_GUARD,
					},
				) == SEPTET_TEST_ROOM
				same = _SameOctets(
					buf[:need],
					want,
				)
			)

			if filled != need || !same || !intact {
				t.Fatalf(
					"%d characters: filled %d of %d, %x; want %x, "+
						"and the guard %x unchanged",
					len(text),
					filled,
					need,
					buf[:need],
					want,
					buf[need:],
				)
			}
		}
	}
}

// _CheckSeptetKernels packs one text with a kernel and with the shift, compares the whole
// blocks, and spreads the octets of the shift back with the spread kernel.
//
// Revisions:
//   - 2026-10-21 22:07: initial creation
func _CheckSeptetKernels(
	t *testing.T,
	pack *_SeptetKernel,
	spread *_SeptetKernel,
	text []byte,
) {
	t.Helper()

	var (
		room = len(text)*SEPTET_BITS/BITS_PER_BYTE + SEPTET_TEST_ROOM
		want = make(
			[]byte,
			room,
		)
		got = make(
			[]byte,
			room,
		)
		whole  = len(text) / pack.block * pack.block
		octets = whole * SEPTET_BITS / BITS_PER_BYTE
	)

	_PackSeptetsShift(
		want,
		text,
	)

	var (
		done = pack.run(
			got,
			text,
		)
		same = _SameOctets(
			got[:octets],
			want[:octets],
		)
	)

	if done != whole || !same {
		t.Fatalf(
			"%s pack of %d characters: %d done, %x; want %d, %x",
			pack.name,
			len(text),
			done,
			got[:octets],
			whole,
			want[:octets],
		)
	}

	var (
		back = make(
			[]byte,
			len(text),
		)
		moved = spread.run(
			back,
			want,
		)
		equal = _SameOctets(
			back[:whole],
			text[:whole],
		)
	)

	if moved != whole || !equal {
		t.Fatalf(
			"%s spread of %d characters: %d done, %x; want %d, %x",
			spread.name,
			len(text),
			moved,
			back[:whole],
			whole,
			text[:whole],
		)
	}
}

// _SeptetSizes is 0 to SEPTET_TEST_SHORT, then SEPTET_TEST_LONG.
//
// Revisions:
//   - 2026-10-21 22:07: initial creation
func _SeptetSizes() []int {
	sizes := make(
		[]int,
		0,
		SEPTET_TEST_SHORT+1+len(SEPTET_TEST_LONG),
	)
	for size := range SEPTET_TEST_SHORT + 1 {
		sizes = append(
			sizes,
			size,
		)
	}

	return append(
		sizes,
		SEPTET_TEST_LONG...,
	)
}

// _SeptetTexts gives three texts of size 7-bit characters: a mix, all bits set, and none.
//
// Revisions:
//   - 2026-10-21 22:07: initial creation
func _SeptetTexts(size int) [][]byte {
	var (
		mixed = make(
			[]byte,
			size,
		)
		full = bytes.Repeat(
			[]byte{
				SEPTET_TEST_TOP,
			},
			size,
		)
		empty = make(
			[]byte,
			size,
		)
	)

	for idx := range mixed {
		mixed[idx] = byte(idx*SEPTET_TEST_STRIDE+SEPTET_TEST_SEED) & SEPTET_TEST_TOP
	}

	return [][]byte{
		mixed,
		full,
		empty,
	}
}

// _SameOctets compares two octet strings.
//
// Revisions:
//   - 2026-10-21 22:07: initial creation
func _SameOctets(
	first,
	second []byte,
) bool {
	return bytes.Equal(
		first,
		second,
	)
}
