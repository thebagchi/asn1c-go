package per_test

import (
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// BenchmarkIA5DecodeMisaligned times DecodeRestrictedString for an IA5String after one bit,
// the decode row of P13-4 with one leading bit. In UPER the bit puts every 7-bit field off an
// octet boundary. The octets are built once, outside the timed loop, and the bit is read in
// the loop, as the encode bench writes it.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func BenchmarkIA5DecodeMisaligned(b *testing.B) {
	for _, item := range VARIANTS {
		for _, size := range IA5_SIZES {
			encoded := _IA5EncodedAfterBit(
				b,
				item,
				_IA5Text(size),
			)

			b.Run(
				item.name+"/"+strconv.Itoa(size),
				func(b *testing.B) {
					b.SetBytes(int64(size))
					b.ReportAllocs()

					for b.Loop() {
						dec := item.decoder(encoded)
						if _, err := dec.DecodeBoolean(); err != nil {
							b.Fatal(err)
						}

						_, err := dec.DecodeRestrictedString(
							per.STRING_IA5,
							per.Unconstrained(),
						)
						if err != nil {
							b.Fatal(err)
						}
					}
				},
			)
		}
	}
}

// _IA5EncodedAfterBit returns the octets of IA5_OFFSET bits and then value.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation
func _IA5EncodedAfterBit(
	b *testing.B,
	item *_Variant,
	value string,
) []byte {
	b.Helper()

	enc := item.encoder()
	if err := _IA5Offset(enc); err != nil {
		b.Fatal(err)
	}

	err := enc.EncodeRestrictedString(
		value,
		per.STRING_IA5,
		per.Unconstrained(),
	)
	if err != nil {
		b.Fatal(err)
	}

	return enc.Bytes()
}
