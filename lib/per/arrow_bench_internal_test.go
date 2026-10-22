package per

import (
	"testing"

	"github.com/apache/arrow-go/v18/arrow/bitutil"
)

// This file is an internal test because _PackSeptets is unexported.
// The Arrow calls are the comparison. Apache License 2.0. The codec does not import Arrow.

// The character counts the comparison times.
const (
	ARROW_CHARS_SHORT = 8
	ARROW_CHARS_BLOCK = 64
	ARROW_CHARS_LONG  = 1024
)

// TestArrow_PackAgrees checks a 7-bit pack through Arrow SetBit and ClearBit
// against _PackSeptets. Arrow numbers the low bit first, so each bit index is
// flipped inside its byte.
//
// Revisions:
//   - 2026-10-21 03:04: initial creation
func TestArrow_PackAgrees(t *testing.T) {
	cases := []int{
		1,
		2,
		7,
		ARROW_CHARS_SHORT,
		ARROW_CHARS_BLOCK,
		ARROW_CHARS_BLOCK + 1,
		ARROW_CHARS_LONG,
	}

	for _, size := range cases {
		var (
			text = _ArrowText(size)
			ours = make(
				[]byte,
				_SeptetOctets(size),
			)
			arrow = make(
				[]byte,
				len(ours),
			)
			filled = _PackSeptets(
				ours,
				text,
			)

			got = _PackArrow(
				arrow,
				text,
			)
		)
		if got != filled || string(arrow[:filled]) != string(ours[:filled]) {
			t.Fatalf(
				"size %d arrow %d %x, septets %d %x",
				size,
				got,
				arrow[:filled],
				filled,
				ours[:filled],
			)
		}
	}
}

// BenchmarkArrowPack times a 7-bit pack. ours is _PackSeptets. arrow sets each
// bit through bitutil.
//
// Revisions:
//   - 2026-10-21 03:04: initial creation
func BenchmarkArrowPack(b *testing.B) {
	cases := []struct {
		name string
		size int
	}{
		{
			name: "8",
			size: ARROW_CHARS_SHORT,
		},
		{
			name: "64",
			size: ARROW_CHARS_BLOCK,
		},
		{
			name: "1024",
			size: ARROW_CHARS_LONG,
		},
	}

	for _, tc := range cases {
		var (
			text = _ArrowText(tc.size)
			ours = make(
				[]byte,
				_SeptetOctets(tc.size),
			)
			arrow = make(
				[]byte,
				len(ours),
			)
		)

		b.Run(
			"ours/"+tc.name,
			func(b *testing.B) {
				b.SetBytes(int64(tc.size))
				b.ReportAllocs()

				var filled int
				for b.Loop() {
					filled = _PackSeptets(
						ours,
						text,
					)
				}

				if filled == 0 {
					b.Fatal("pack")
				}
			},
		)
		b.Run(
			"arrow/"+tc.name,
			func(b *testing.B) {
				b.SetBytes(int64(tc.size))
				b.ReportAllocs()

				var filled int
				for b.Loop() {
					filled = _PackArrow(
						arrow,
						text,
					)
				}

				if filled == 0 {
					b.Fatal("pack")
				}
			},
		)
	}
}

// _PackArrow packs 7-bit characters with Arrow's bit writer.
//
// Revisions:
//   - 2026-10-21 03:04: initial creation
func _PackArrow(
	dst []byte,
	text []byte,
) int {
	bit := 0

	for _, char := range text {
		for shift := SEPTET_BITS - 1; shift >= 0; shift-- {
			index := bit ^ (BITS_PER_BYTE - 1)
			if char&(1<<shift) != 0 {
				bitutil.SetBit(
					dst,
					index,
				)
			} else {
				bitutil.ClearBit(
					dst,
					index,
				)
			}

			bit++
		}
	}

	if bit == 0 {
		return 0
	}

	return (bit + BITS_PER_BYTE - 1) / BITS_PER_BYTE
}

// _ArrowText is size copies of A, one IA5 character.
//
// Revisions:
//   - 2026-10-21 03:04: initial creation
func _ArrowText(size int) []byte {
	text := make(
		[]byte,
		size,
	)
	for index := range text {
		text[index] = 'A'
	}

	return text
}

// _SeptetOctets is the octets size 7-bit characters can fill.
//
// Revisions:
//   - 2026-10-21 03:04: initial creation
func _SeptetOctets(size int) int {
	return (size*SEPTET_BITS + BITS_PER_BYTE - 1) / BITS_PER_BYTE
}
