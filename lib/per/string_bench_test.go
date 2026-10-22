package per_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// IA5_OFFSET is the single bit in front of BenchmarkIA5EncodeMisaligned.
const (
	IA5_OFFSET = 1
)

// IA5_SIZES are the lengths of the IA5String baseline.
// Eight characters is a short field.
// Sixty-four is one AVX2 block of a later kernel.
// 1024 is long enough for a per-character loop to show.
var (
	IA5_SIZES = []int{
		8,
		64,
		1024,
	}
)

// BenchmarkIA5Encode times EncodeRestrictedString for an IA5String.
// The encoder starts on an octet boundary.
// The allocation of the encoder is the same in every variant.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func BenchmarkIA5Encode(b *testing.B) {
	for _, item := range VARIANTS {
		for _, size := range IA5_SIZES {
			value := _IA5Text(size)

			b.Run(
				item.name+"/"+strconv.Itoa(size),
				func(b *testing.B) {
					b.SetBytes(int64(size))
					b.ReportAllocs()

					for b.Loop() {
						var (
							enc = item.encoder()

							err = enc.EncodeRestrictedString(
								value,
								per.STRING_IA5,
								per.Unconstrained(),
							)
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

// BenchmarkIA5Decode times DecodeRestrictedString for an IA5String.
// The octets are built once, outside the timed loop.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func BenchmarkIA5Decode(b *testing.B) {
	for _, item := range VARIANTS {
		for _, size := range IA5_SIZES {
			encoded := _IA5Encoded(
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
						var (
							dec = item.decoder(encoded)

							_, err = dec.DecodeRestrictedString(
								per.STRING_IA5,
								per.Unconstrained(),
							)
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

// BenchmarkIA5EncodeMisaligned times an IA5String after one bit.
// The bit puts the character field off an octet boundary.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func BenchmarkIA5EncodeMisaligned(b *testing.B) {
	for _, item := range VARIANTS {
		for _, size := range IA5_SIZES {
			value := _IA5Text(size)

			b.Run(
				item.name+"/"+strconv.Itoa(size),
				func(b *testing.B) {
					b.SetBytes(int64(size))
					b.ReportAllocs()

					for b.Loop() {
						var (
							enc = item.encoder()

							err = _IA5Offset(enc)
						)
						if err != nil {
							b.Fatal(err)
						}

						err = enc.EncodeRestrictedString(
							value,
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

// _IA5Text returns length copies of "A", which is one IA5 character.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func _IA5Text(length int) string {
	return strings.Repeat(
		"A",
		length,
	)
}

// _IA5Encoded encodes value with no bit in front of it.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func _IA5Encoded(
	b *testing.B,
	item *_Variant,
	value string,
) []byte {
	b.Helper()

	var (
		enc = item.encoder()

		err = enc.EncodeRestrictedString(
			value,
			per.STRING_IA5,
			per.Unconstrained(),
		)
	)
	if err != nil {
		b.Fatal(err)
	}

	return enc.Bytes()
}

// _IA5Offset writes IA5_OFFSET bits, so the next field starts mid-byte.
//
// Revisions:
//   - 2026-10-20 00:32: initial creation
func _IA5Offset(enc *per.Encoder) error {
	for range IA5_OFFSET {
		if err := enc.EncodeBoolean(true); err != nil {
			return err
		}
	}

	return nil
}
