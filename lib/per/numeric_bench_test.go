package per_test

import (
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _Variant is one PER _Variant with its constructors, so that no helper in these
// tests takes a bare true or false and decides what it means.
type _Variant struct {
	name    string
	encoder func() *per.Encoder
	decoder func([]byte) *per.Decoder
}

// The two variants, and the sizes and offset the NumericString paths are timed
// at. 16 characters is one SSE2 block and half an AVX2 one, so it shows what
// the kernel costs when it barely runs; 1024 is where the per-character loop
// it replaced dominated. The offset puts the codec three bits into a byte, so
// the packed characters go through the shifted paths - the case a real
// message is in after a preamble.
var (
	UPER = &_Variant{
		name:    "uper",
		encoder: per.NewUnalignedEncoder,
		decoder: per.NewUnalignedDecoder,
	}
	APER = &_Variant{
		name:    "aper",
		encoder: per.NewAlignedEncoder,
		decoder: per.NewAlignedDecoder,
	}
	VARIANTS      = []*_Variant{UPER, APER}
	NUMERIC_SIZES = []int{16, 64, 1024}
)

const (
	NUMERIC_OFFSET = 3
)

// BenchmarkNumericStringEncode times EncodeRestrictedString for a NumericString
// in both variants.
//
// The encoder is created inside the loop because the codec has no reset, and
// that allocation is the same in every variant being compared, so it cancels.
//
// Revisions:
//   - 2026-09-23 05:20: initial creation
//   - 2026-09-23 07:05: variants as a table rather than a boolean
func BenchmarkNumericStringEncode(b *testing.B) {
	for _, item := range VARIANTS {
		for _, size := range NUMERIC_SIZES {
			value := _NumericText(
				size,
				0,
			)

			b.Run(
				item.name+"/"+strconv.Itoa(size),
				func(b *testing.B) {
					b.SetBytes(int64(size))
					b.ReportAllocs()

					for b.Loop() {
						enc := item.encoder()

						if err := _Misalign(enc); err != nil {
							b.Fatal(err)
						}

						err := enc.EncodeRestrictedString(
							value,
							per.STRING_NUMERIC,
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

// BenchmarkNumericStringDecode times DecodeRestrictedString for a NumericString
// in both variants. The encoded buffer is built once, outside the timed loop.
//
// Revisions:
//   - 2026-09-23 05:20: initial creation
//   - 2026-09-23 07:05: variants as a table rather than a boolean
func BenchmarkNumericStringDecode(b *testing.B) {
	for _, item := range VARIANTS {
		for _, size := range NUMERIC_SIZES {
			encoded := _NumericEncoded(
				b,
				item,
				_NumericText(
					size,
					0,
				),
			)

			b.Run(
				item.name+"/"+strconv.Itoa(size),
				func(b *testing.B) {
					b.SetBytes(int64(size))
					b.ReportAllocs()

					for b.Loop() {
						dec := item.decoder(encoded)

						for range NUMERIC_OFFSET {
							_, err := dec.DecodeBoolean()
							if err != nil {
								b.Fatal(err)
							}
						}

						_, err := dec.DecodeRestrictedString(
							per.STRING_NUMERIC,
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

// _NumericText builds a deterministic NumericString of the given length.
// testing/numeric_offset.py uses the same rule, so a test can rebuild the value
// of a numeric_offset row of testing.json from its length and seed alone.
//
// Revisions:
//   - 2026-09-23 05:20: initial creation
func _NumericText(
	length,
	seed int,
) string {
	const (
		ALPHABET = " 0123456789"
		STRIDE   = 7
	)

	out := make(
		[]byte,
		length,
	)
	for idx := range out {
		out[idx] = ALPHABET[(idx*STRIDE+seed)%len(ALPHABET)]
	}

	return string(out)
}

// _NumericEncoded encodes one value behind NUMERIC_OFFSET bits.
//
// Revisions:
//   - 2026-09-23 05:20: initial creation
//   - 2026-09-23 07:05: takes the variant rather than a boolean
func _NumericEncoded(
	b *testing.B,
	item *_Variant,
	value string,
) []byte {
	b.Helper()

	enc := item.encoder()

	if err := _Misalign(enc); err != nil {
		b.Fatal(err)
	}

	err := enc.EncodeRestrictedString(
		value,
		per.STRING_NUMERIC,
		per.Unconstrained(),
	)
	if err != nil {
		b.Fatal(err)
	}

	return enc.Bytes()
}

// _Misalign writes NUMERIC_OFFSET bits, so what follows is not octet-aligned.
//
// Revisions:
//   - 2026-09-23 05:20: initial creation
func _Misalign(enc *per.Encoder) error {
	for range NUMERIC_OFFSET {
		if err := enc.EncodeBoolean(true); err != nil {
			return err
		}
	}

	return nil
}
