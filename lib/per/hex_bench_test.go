package per_test

import (
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// BenchmarkBytesToHex times the hexadecimal rendering.
//
// Revisions:
//   - 2026-09-23 08:30: initial creation
func BenchmarkBytesToHex(b *testing.B) {
	for _, size := range TEXT_SIZES {
		data := _TextPayload(size)

		b.Run(
			strconv.Itoa(size),
			func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				for b.Loop() {
					per.BytesToHex(data)
				}
			},
		)
	}
}

// BenchmarkHexToBytes times the hexadecimal parse.
//
// Revisions:
//   - 2026-09-23 08:30: initial creation
func BenchmarkHexToBytes(b *testing.B) {
	for _, size := range TEXT_SIZES {
		text := per.BytesToHex(_TextPayload(size))

		b.Run(
			strconv.Itoa(size),
			func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				for b.Loop() {
					if _, err := per.HexToBytes(text); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}
