package per

import (
	"strconv"
	"strings"
	"testing"
)

// This file is an internal test because the Go pack it compares with is unexported.

// BITSTRING_BENCH_OCTET is the eight characters the texts of BenchmarkParseBitString repeat.
const (
	BITSTRING_BENCH_OCTET = "10110001"
)

// BITSTRING_BENCH_SIZES are the text lengths of BenchmarkParseBitString: one AVX2 block, and
// a long text. BITSTRING_BENCH_SINK keeps the octets of the Go pack, so they leave the call
// as the octets of ParseBitString do and both make one allocation.
var (
	BITSTRING_BENCH_SIZES = []int{
		64,
		70000,
	}
	BITSTRING_BENCH_SINK []byte
)

// BenchmarkParseBitString compares the Go pack with the path ParseBitString takes, the
// kernels and then the Go pack (review P31). Both make the one allocation of the octets per
// call. The level names path= and size= let benchstat set the two paths side by side with
// -col /path.
//
// Revisions:
//   - 2026-10-21 21:53: initial creation (review P31)
func BenchmarkParseBitString(b *testing.B) {
	for _, size := range BITSTRING_BENCH_SIZES {
		text := strings.Repeat(
			BITSTRING_BENCH_OCTET,
			size/BITS_PER_BYTE,
		)

		b.Run(
			"path=go/size="+strconv.Itoa(size),
			func(b *testing.B) {
				_BenchParseGo(
					b,
					text,
				)
			},
		)
		b.Run(
			"path=kernel/size="+strconv.Itoa(size),
			func(b *testing.B) {
				_BenchParseKernel(
					b,
					text,
				)
			},
		)
	}
}

// _BenchParseGo times the Go pack alone on a text of whole octets.
//
// Revisions:
//   - 2026-10-21 21:53: initial creation
func _BenchParseGo(
	b *testing.B,
	text string,
) {
	b.Helper()

	src := _StringBytes(text)

	b.SetBytes(int64(len(src)))
	b.ReportAllocs()

	for b.Loop() {
		var (
			data = make(
				[]byte,
				len(src)/BITS_PER_BYTE,
			)
			done = _BinaryDecodeGo(
				data,
				src,
			)
		)

		if done != len(src) {
			b.Fatal("the Go pack stopped early")
		}

		BITSTRING_BENCH_SINK = data
	}
}

// _BenchParseKernel times ParseBitString on the same text.
//
// Revisions:
//   - 2026-10-21 21:53: initial creation
func _BenchParseKernel(
	b *testing.B,
	text string,
) {
	b.Helper()

	b.SetBytes(int64(len(text)))
	b.ReportAllocs()

	for b.Loop() {
		if _, err := ParseBitString(text); err != nil {
			b.Fatal(err)
		}
	}
}
