package per_test

import (
	"encoding/asn1"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// BenchmarkBitStringToBinary times the '0'/'1' rendering of a bit string.
//
// Revisions:
//   - 2026-09-23 08:30: initial creation
func BenchmarkBitStringToBinary(b *testing.B) {
	for _, size := range TEXT_SIZES {
		value := &asn1.BitString{
			Bytes:     textPayload(size),
			BitLength: size * per.BITS_PER_BYTE,
		}

		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()

			for b.Loop() {
				per.BitStringToBinary(value)
			}
		})
	}
}

// BenchmarkBitStringFromBinary times the '0'/'1' parse into a bit string.
//
// Revisions:
//   - 2026-09-23 08:30: initial creation
func BenchmarkBitStringFromBinary(b *testing.B) {
	for _, size := range TEXT_SIZES {
		text := per.BitStringToBinary(&asn1.BitString{
			Bytes:     textPayload(size),
			BitLength: size * per.BITS_PER_BYTE,
		})

		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()

			for b.Loop() {
				if _, err := per.BitStringFromBinary(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
