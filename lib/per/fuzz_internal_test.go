package per

import (
	"reflect"
	"testing"
)

// This file is an internal test because the round trip compares the bits two encodings hold,
// and only the codec of each encoder knows how many bits it wrote.

// FUZZ_ALIGNED is the bit of the variant octet that picks the ALIGNED variant, and
// FUZZ_UNALIGNED the octet of the other one.
const (
	FUZZ_ALIGNED   = 0x01
	FUZZ_UNALIGNED = 0x00
)

// FUZZ_INTEGER_SEED is the value of the INTEGER seeds: inside every size of FuzzDecodeInteger.
const (
	FUZZ_INTEGER_SEED = 5
)

// _Pair is one decoder under fuzz, the encoder that writes its value back, and how two
// values compare. A nil equal compares with reflect.DeepEqual; a value that holds a
// time.Time or a float that can be NaN gives its own.
type _Pair[V any] struct {
	decode func(dec *Decoder) (V, error)
	encode func(
		enc *Encoder,
		value V,
	) error
	equal func(
		first,
		second V,
	) bool
}

// _Encoding is what one encoder wrote: its octets and how many bits of them count.
type _Encoding struct {
	octets []byte
	bits   uint64
}

// FuzzDecodeBoolean guards review P29-3 for DecodeBoolean.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation (review P29-3)
//   - 2026-10-21 18:56: the seeds come from the encoder, with their variant octet
//   - 2026-10-21 20:55: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeBoolean(f *testing.F) {
	pair := &_Pair[bool]{
		decode: (*Decoder).DecodeBoolean,
		encode: (*Encoder).EncodeBoolean,
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

// FuzzDecodeInteger guards review P29-3 for DecodeInteger. The first octet picks one of the
// sizes below, and the harness reads the rest.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation (review P29-3)
//   - 2026-10-21 18:56: the seeds come from the encoder, with their variant octet
//   - 2026-10-21 20:55: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeInteger(f *testing.F) {
	sizes := []*Constraint{
		Unconstrained(),
		Constrained(
			0,
			255,
		),
		Constrained(
			-5,
			70000,
		),
		SemiConstrained(-1),
		Constrained(
			0,
			7,
		).Extensible(),
	}

	for pick, size := range sizes {
		_FuzzSeedValue(
			f,
			[]byte{
				byte(pick),
			},
			_IntegerPair(size),
			FUZZ_INTEGER_SEED,
		)
	}

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
				_IntegerPair(size),
			)
		},
	)
}

// _IntegerPair is the pair of FuzzDecodeInteger under one size.
//
// Revisions:
//   - 2026-10-21 20:55: initial creation, split out of FuzzDecodeInteger (review P30)
func _IntegerPair(size *Constraint) *_Pair[int64] {
	return &_Pair[int64]{
		decode: func(dec *Decoder) (int64, error) {
			return dec.DecodeInteger(size)
		},
		encode: func(
			enc *Encoder,
			value int64,
		) error {
			return enc.EncodeInteger(
				value,
				size,
			)
		},
	}
}

// _FuzzRoundTrip runs one pair on data. The first octet picks the variant (see FUZZ_ALIGNED)
// and the decoder reads the rest. The decoder must not panic. A value that decodes must
// encode; that encoding must decode to an equal value, and that value must encode to the
// same bits again. A decoder may accept a longer form or a pad bit that is not zero, so the
// input itself is not compared (review P30).
//
// Revisions:
//   - 2026-10-21 18:08: initial creation (review P29-3)
//   - 2026-10-21 18:56: the first octet picks the variant, in place of both variants on
//     every input
//   - 2026-10-21 20:55: two trips through the encoder, in place of a compare with the input
//     (review P30)
func _FuzzRoundTrip[V any](
	t *testing.T,
	data []byte,
	pair *_Pair[V],
) {
	t.Helper()

	if len(data) == 0 {
		return
	}

	var (
		variant = data[0] & FUZZ_ALIGNED

		value, err = pair.decode(_FuzzDecoder(
			variant,
			data[1:],
		))
	)
	if err != nil {
		return
	}

	var first = _FuzzEncode(
		t,
		variant,
		pair,
		value,
	)

	again, err := pair.decode(_FuzzDecoder(
		variant,
		first.octets,
	))
	if err != nil {
		t.Fatalf(
			"variant %d: %x decodes to %v, whose encoding %x does not decode: %v",
			variant,
			data,
			value,
			first.octets,
			err,
		)
	}

	_CheckSameValue(
		t,
		pair,
		value,
		again,
	)

	second := _FuzzEncode(
		t,
		variant,
		pair,
		again,
	)
	if second.bits != first.bits || string(second.octets) != string(first.octets) {
		t.Fatalf(
			"variant %d: %v encodes to %d bits %x, then to %d bits %x",
			variant,
			value,
			first.bits,
			first.octets,
			second.bits,
			second.octets,
		)
	}
}

// _FuzzSeedValue adds value as a seed in both variants, behind prefix (the octets _Pick
// reads, or nil) and the variant octet. Each seed must decode to value, so a seed is an
// encoding the decoder reads back, not only one the encoder wrote.
//
// Revisions:
//   - 2026-10-21 20:55: initial creation (review P30)
func _FuzzSeedValue[V any](
	f *testing.F,
	prefix []byte,
	pair *_Pair[V],
	value V,
) {
	f.Helper()

	for _, variant := range []byte{
		FUZZ_ALIGNED,
		FUZZ_UNALIGNED,
	} {
		var (
			encoding = _FuzzEncode(
				f,
				variant,
				pair,
				value,
			)

			back, err = pair.decode(_FuzzDecoder(
				variant,
				encoding.octets,
			))
		)
		if err != nil {
			f.Fatalf(
				"variant %d: the seed %v, %x, does not decode: %v",
				variant,
				value,
				encoding.octets,
				err,
			)
		}

		_CheckSameValue(
			f,
			pair,
			value,
			back,
		)

		seed := append(
			append(
				append(
					[]byte{},
					prefix...,
				),
				variant,
			),
			encoding.octets...,
		)
		f.Add(seed)
	}
}

// _FuzzEncode encodes value in the variant FUZZ_ALIGNED or FUZZ_UNALIGNED names. A value the
// decoder gave back must encode.
//
// Revisions:
//   - 2026-10-21 20:55: initial creation (review P30)
func _FuzzEncode[V any](
	tb testing.TB,
	variant byte,
	pair *_Pair[V],
	value V,
) *_Encoding {
	tb.Helper()

	enc := NewUnalignedEncoder()
	if variant == FUZZ_ALIGNED {
		enc = NewAlignedEncoder()
	}

	if err := pair.encode(
		enc,
		value,
	); err != nil {
		tb.Fatalf(
			"variant %d: %v does not encode: %v",
			variant,
			value,
			err,
		)
	}

	return &_Encoding{
		octets: enc.codec.Bytes(),
		bits:   enc.codec.NumWritten(),
	}
}

// _FuzzDecoder returns a decoder of data in the variant FUZZ_ALIGNED or FUZZ_UNALIGNED names.
//
// Revisions:
//   - 2026-10-21 20:55: initial creation (review P30)
func _FuzzDecoder(
	variant byte,
	data []byte,
) *Decoder {
	if variant == FUZZ_ALIGNED {
		return NewAlignedDecoder(data)
	}

	return NewUnalignedDecoder(data)
}

// _CheckSameValue fails when two values of a pair differ.
//
// Revisions:
//   - 2026-10-21 20:55: initial creation (review P30)
func _CheckSameValue[V any](
	tb testing.TB,
	pair *_Pair[V],
	first,
	second V,
) {
	tb.Helper()

	same := reflect.DeepEqual(
		first,
		second,
	)
	if pair.equal != nil {
		same = pair.equal(
			first,
			second,
		)
	}

	if !same {
		tb.Fatalf(
			"%v decodes back as %v",
			first,
			second,
		)
	}
}

// _Pick takes the first octet of data as a choice among options, and returns the choice
// and the octets after it. No data picks the first option.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation (review P29-3)
func _Pick[T any](
	data []byte,
	options []T,
) (T, []byte) {
	if len(data) == 0 {
		return options[0], data
	}

	return options[int(data[0])%len(options)], data[1:]
}
