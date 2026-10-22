package per_test

import (
	"encoding/asn1"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// BenchmarkFormatBitString times the '0'/'1' rendering of a bit string.
//
// Revisions:
//   - 2026-09-23 08:30: initial creation, as BenchmarkBitStringToBinary
//   - 2026-10-21 21:38: FormatBitString, which replaced BitStringToBinary (review P31)
func BenchmarkFormatBitString(b *testing.B) {
	for _, size := range TEXT_SIZES {
		value := &asn1.BitString{
			Bytes:     _TextPayload(size),
			BitLength: size * per.BITS_PER_BYTE,
		}

		b.Run(
			strconv.Itoa(size),
			func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				for b.Loop() {
					if _, err := per.FormatBitString(value); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}
