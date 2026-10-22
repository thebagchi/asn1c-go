package per

import (
	"encoding/asn1"
	"testing"
)

// This file is an internal test because the harness reads the codec counts.

// _EmptyBitmap returns a bit string of count bits with no bit set. It is the value that a
// decoder of a preamble or an additions bitmap fills.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func _EmptyBitmap(count int) *asn1.BitString {
	return &asn1.BitString{
		Bytes: make(
			[]byte,
			(count+BITS_PER_BYTE-1)/BITS_PER_BYTE,
		),
		BitLength: count,
	}
}

// _NewBitmap returns a bit string of count bits with the bits at the even positions set. It
// is the value that the caller of a preamble or an additions bitmap passes.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func _NewBitmap(count int) *asn1.BitString {
	value := _EmptyBitmap(count)

	for bit := 0; bit < count; bit += 2 {
		value.Bytes[bit/BITS_PER_BYTE] |= 0x80 >> (bit % BITS_PER_BYTE)
	}

	return value
}

// _NewWords returns the words of count bits with the bits at the even positions set.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func _NewWords(count uint64) []uint64 {
	words := OptionalBitmap(count)

	for bit := uint64(0); bit < count; bit += 2 {
		BitmapSet(
			words,
			bit,
		)
	}

	return words
}

// FuzzDecodeBitString guards review P29-3 for DecodeBitString. The first octet picks one of
// the sizes below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeBitString(f *testing.F) {
	sizes := []*Constraint{
		Unconstrained(),
		Constrained(
			0,
			255,
		),
		Constrained(
			12,
			12,
		),
		Constrained(
			1,
			20,
		).Extensible(),
		Constrained(
			0,
			70000,
		),
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_BitStringPair(sizes[0]),
		_NewBitmap(13),
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(3),
		},
		_BitStringPair(sizes[3]),
		_NewBitmap(5),
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			size, rest := _Pick(
				data,
				sizes,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_BitStringPair(size),
			)
		},
	)
}

// _BitStringPair is the pair of FuzzDecodeBitString under one size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeBitString (review P30)
func _BitStringPair(size *Constraint) *_Pair[*asn1.BitString] {
	return &_Pair[*asn1.BitString]{
		decode: func(dec *Decoder) (*asn1.BitString, error) {
			return dec.DecodeBitString(size)
		},
		encode: func(
			enc *Encoder,
			value *asn1.BitString,
		) error {
			return enc.EncodeBitString(
				value,
				size,
			)
		},
	}
}

// FuzzReadBits guards review P29-3 for ReadBits. The first octet picks one of the counts
// below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzReadBits(f *testing.F) {
	counts := []uint64{
		1,
		7,
		8,
		64,
		100,
		300,
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(1),
		},
		_ReadBitsPair(counts[1]),
		_NewBitmap(7).Bytes,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(4),
		},
		_ReadBitsPair(counts[4]),
		_NewBitmap(100).Bytes,
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			count, rest := _Pick(
				data,
				counts,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_ReadBitsPair(count),
			)
		},
	)
}

// _ReadBitsPair is the pair of FuzzReadBits under one bit count.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzReadBits (review P30)
func _ReadBitsPair(count uint64) *_Pair[[]byte] {
	return &_Pair[[]byte]{
		decode: func(dec *Decoder) ([]byte, error) {
			return dec.ReadBits(count)
		},
		encode: func(
			enc *Encoder,
			value []byte,
		) error {
			return enc.WriteBits(
				value,
				count,
			)
		},
	}
}

// FuzzReadExtensionBit guards review P29-3 for ReadExtensionBit.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzReadExtensionBit(f *testing.F) {
	pair := &_Pair[bool]{
		decode: (*Decoder).ReadExtensionBit,
		encode: (*Encoder).WriteExtensionBit,
	}

	for _, value := range []bool{
		true,
		false,
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}

// FuzzReadOptional guards review P29-3 for ReadOptional. The first octet picks one of the bit
// counts below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzReadOptional(f *testing.F) {
	counts := []uint64{
		1,
		5,
		64,
		70,
		65536,
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(1),
		},
		_ReadOptionalPair(counts[1]),
		_NewWords(counts[1]),
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(3),
		},
		_ReadOptionalPair(counts[3]),
		_NewWords(counts[3]),
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			count, rest := _Pick(
				data,
				counts,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_ReadOptionalPair(count),
			)
		},
	)
}

// _ReadOptionalPair is the pair of FuzzReadOptional under one bit count.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzReadOptional (review P30)
func _ReadOptionalPair(count uint64) *_Pair[[]uint64] {
	return &_Pair[[]uint64]{
		decode: func(dec *Decoder) ([]uint64, error) {
			words := OptionalBitmap(count)

			return words, dec.ReadOptional(
				words,
				count,
			)
		},
		encode: func(
			enc *Encoder,
			value []uint64,
		) error {
			return enc.WriteOptional(
				value,
				count,
			)
		},
	}
}

// FuzzDecodePreamble guards review P29-3 for DecodePreamble. The first octet picks one of the
// bit counts below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodePreamble(f *testing.F) {
	counts := []int{
		1,
		5,
		64,
		70,
		65536,
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(1),
		},
		_PreamblePair(counts[1]),
		_NewBitmap(counts[1]),
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(3),
		},
		_PreamblePair(counts[3]),
		_NewBitmap(counts[3]),
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			count, rest := _Pick(
				data,
				counts,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_PreamblePair(count),
			)
		},
	)
}

// _PreamblePair is the pair of FuzzDecodePreamble under one bit count.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodePreamble (review P30)
func _PreamblePair(count int) *_Pair[*asn1.BitString] {
	return &_Pair[*asn1.BitString]{
		decode: func(dec *Decoder) (*asn1.BitString, error) {
			value := _EmptyBitmap(count)

			return value, dec.DecodePreamble(value)
		},
		encode: (*Encoder).EncodePreamble,
	}
}

// FuzzDecodeAdditions guards review P29-3 for DecodeAdditions. The first octet picks one of the
// known bit counts below. The decoder drops the additions that the caller does not know, and
// keeps no count of the bits that the sender declared, so no encoder can write the same
// bitmap back. The check is that no input panics.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func FuzzDecodeAdditions(f *testing.F) {
	counts := []int{
		1,
		5,
		64,
		100,
	}

	_FuzzSeedPick(
		f,
		1,
		func(enc *Encoder) error {
			return enc.EncodeAdditions(_NewBitmap(counts[1]))
		},
	)
	_FuzzSeedPick(
		f,
		3,
		func(enc *Encoder) error {
			return enc.EncodeAdditions(_NewBitmap(counts[3]))
		},
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			count, rest := _Pick(
				data,
				counts,
			)

			_FuzzDecodeOnly(
				t,
				rest,
				func(dec *Decoder) error {
					var (
						value = _EmptyBitmap(count)

						_, err = dec.DecodeAdditions(value)
					)

					return err
				},
			)
		},
	)
}

// FuzzReadExtension guards review P29-3 for ReadExtension. The first octet picks one of the
// known bit counts below. The decoder drops the additions that the caller does not know, and
// keeps no count of the bits that the sender declared, so no encoder can write the same
// bitmap back. The check is that no input panics.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func FuzzReadExtension(f *testing.F) {
	counts := []uint64{
		1,
		5,
		64,
		100,
	}

	_FuzzSeedPick(
		f,
		1,
		func(enc *Encoder) error {
			return enc.WriteExtension(
				_NewWords(counts[1]),
				counts[1],
			)
		},
	)
	_FuzzSeedPick(
		f,
		3,
		func(enc *Encoder) error {
			return enc.WriteExtension(
				_NewWords(counts[3]),
				counts[3],
			)
		},
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			count, rest := _Pick(
				data,
				counts,
			)

			_FuzzDecodeOnly(
				t,
				rest,
				func(dec *Decoder) error {
					_, err := dec.ReadExtension(
						ExtensionBitmap(count),
						count,
					)

					return err
				},
			)
		},
	)
}

// FuzzDecodeOpenType guards review P29-3 for DecodeOpenType.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeOpenType(f *testing.F) {
	pair := &_Pair[[]byte]{
		decode: (*Decoder).DecodeOpenType,
		encode: (*Encoder).EncodeOpenType,
	}

	for _, value := range [][]byte{
		{1, 2, 3},
		make(
			[]byte,
			300,
		),
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}

// FuzzSkipOpenTypes guards review P29-3 for SkipOpenTypes. The first octet picks one of the
// counts below. The decoder steps over the octets and keeps none, so no encoder can write
// them back. The check is that no input panics.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func FuzzSkipOpenTypes(f *testing.F) {
	counts := []uint64{
		0,
		1,
		2,
		5,
	}

	_FuzzSeedPick(
		f,
		2,
		func(enc *Encoder) error {
			for range counts[2] {
				if err := enc.EncodeOpenType([]byte{1, 2, 3}); err != nil {
					return err
				}
			}

			return nil
		},
	)
	_FuzzSeedPick(
		f,
		1,
		func(enc *Encoder) error {
			return enc.EncodeOpenType(make(
				[]byte,
				300,
			))
		},
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			count, rest := _Pick(
				data,
				counts,
			)

			_FuzzDecodeOnly(
				t,
				rest,
				func(dec *Decoder) error {
					return dec.SkipOpenTypes(count)
				},
			)
		},
	)
}
