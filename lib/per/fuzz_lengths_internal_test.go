package per

import (
	"errors"
	"testing"
)

// This file is an internal test because the harness reads the codec counts.

// ErrFuzzPartial stops FuzzDecodeCount at a first part that more parts follow: that part
// does not give the total, and FuzzDecodeNext checks the whole chain.
var (
	ErrFuzzPartial = errors.New("a first part; FuzzDecodeNext checks the chain")
)

// _Length is a length that a decoder read, and whether a length of a following part comes
// after the octets of this one, X.691 11.9.3.8.
type _Length struct {
	count uint64
	more  bool
}

// _MakeLength returns what a decoder of a length read as a _Length. It takes the three results
// of the decoder as they are.
//
// Revisions:
//   - 2026-10-21 18:53: initial creation (review P29-3)
func _MakeLength(
	count uint64,
	more bool,
	err error,
) (*_Length, error) {
	return &_Length{
		count: count,
		more:  more,
	}, err
}

// _Failure returns the error of an encoder of a length, and drops the length that the encoder
// leaves for the next part, which the round trip does not need.
//
// Revisions:
//   - 2026-10-21 18:53: initial creation (review P29-3)
func _Failure(
	pending uint64,
	err error,
) error {
	return err
}

// _DecodeParts reads the count of the first part, and then the length of every part after it.
// It returns the total.
//
// Revisions:
//   - 2026-10-21 18:53: initial creation (review P29-3)
func _DecodeParts(
	dec *Decoder,
	size *Constraint,
) (uint64, error) {
	var count Count

	if err := dec.DecodeCount(
		&count,
		size,
	); err != nil {
		return 0, err
	}

	for count.More() {
		if err := dec.DecodeNext(&count); err != nil {
			return 0, err
		}
	}

	return uint64(count.End()), nil
}

// FuzzDecodeLengthDeterminant guards review P29-3 for DecodeLengthDeterminant. The first octet
// picks one of the sizes below, and the decoder reads the rest. A value is one part: a count
// of 16384 with more set stands for a first fragment, as a total of 20000 does not decode back.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeLengthDeterminant(f *testing.F) {
	sizes := []*Constraint{
		Unconstrained(),
		Constrained(
			0,
			255,
		),
		Constrained(
			1,
			100,
		),
		Constrained(
			0,
			70000,
		),
		Constrained(
			3,
			3,
		),
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_LengthDeterminantPair(sizes[0]),
		&_Length{
			count: 16384,
			more:  true,
		},
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(2),
		},
		_LengthDeterminantPair(sizes[2]),
		&_Length{
			count: 42,
		},
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
				_LengthDeterminantPair(size),
			)
		},
	)
}

// _LengthDeterminantPair is the pair of FuzzDecodeLengthDeterminant under one size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeLengthDeterminant (review P30)
func _LengthDeterminantPair(size *Constraint) *_Pair[*_Length] {
	return &_Pair[*_Length]{
		decode: func(dec *Decoder) (*_Length, error) {
			return _MakeLength(
				dec.DecodeLengthDeterminant(size),
			)
		},
		encode: func(
			enc *Encoder,
			value *_Length,
		) error {
			return _Failure(enc.EncodeLengthDeterminant(
				value.count,
				size,
			))
		},
	}
}

// FuzzDecodeUnconstrainedLength guards review P29-3 for DecodeUnconstrainedLength. A value is
// one part, so the seed of 32768 with more set is a first fragment.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeUnconstrainedLength(f *testing.F) {
	pair := &_Pair[*_Length]{
		decode: func(dec *Decoder) (*_Length, error) {
			return _MakeLength(dec.DecodeUnconstrainedLength())
		},
		encode: func(
			enc *Encoder,
			value *_Length,
		) error {
			return _Failure(
				enc.EncodeUnconstrainedLength(value.count),
			)
		},
	}

	for _, value := range []*_Length{
		{
			count: 300,
		},
		{
			count: 32768,
			more:  true,
		},
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

// FuzzDecodeNormallySmallLength guards review P29-3 for DecodeNormallySmallLength.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeNormallySmallLength(f *testing.F) {
	pair := &_Pair[*_Length]{
		decode: func(dec *Decoder) (*_Length, error) {
			return _MakeLength(dec.DecodeNormallySmallLength())
		},
		encode: func(
			enc *Encoder,
			value *_Length,
		) error {
			return _Failure(
				enc.EncodeNormallySmallLength(value.count),
			)
		},
	}

	for _, value := range []*_Length{
		{
			count: 9,
		},
		{
			count: 200,
		},
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

// _CountSizes are the sizes that the count fuzz functions pick from: bounded and unbounded,
// extensible, fixed, and with an upper bound of 64K or more, where the parts begin.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
func _CountSizes() []*Constraint {
	return []*Constraint{
		Unconstrained(),
		Constrained(
			0,
			3,
		),
		Constrained(
			2,
			2,
		),
		Constrained(
			0,
			100,
		).Extensible(),
		Constrained(
			0,
			70000,
		),
		Constrained(
			70000,
			70000,
		),
	}
}

// _EncodeParts writes the count of total components and the length of every part after the
// first, as the encoder of a SEQUENCE OF does between the components. It writes no component.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
func _EncodeParts(
	enc *Encoder,
	total uint64,
	size *Constraint,
) error {
	var count Count

	if err := enc.EncodeCount(
		&count,
		total,
		size,
	); err != nil {
		return err
	}

	for count.More() {
		if err := enc.EncodeNext(&count); err != nil {
			return err
		}
	}

	return nil
}

// FuzzDecodeCount guards review P29-3 for DecodeCount. The first octet picks one of the sizes
// below. When the count is one part, the encoder writes a list of that many components, which
// has the same length. When more parts follow, the first part does not give the total, so
// the decode stops with ErrFuzzPartial and FuzzDecodeNext checks that input.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 19:08: stops at a first part that more parts follow: SIZE (70000) read a
//     first part of 16384 and asked the encoder for a total of 16384
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeCount(f *testing.F) {
	sizes := _CountSizes()

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_CountPair(sizes[0]),
		&_Length{
			count: 17,
		},
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(3),
		},
		_CountPair(sizes[3]),
		&_Length{
			count: 150,
		},
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
				_CountPair(size),
			)
		},
	)
}

// _CountPair is the pair of FuzzDecodeCount under one size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeCount (review P30)
func _CountPair(size *Constraint) *_Pair[*_Length] {
	return &_Pair[*_Length]{
		decode: func(dec *Decoder) (*_Length, error) {
			var count Count

			err := dec.DecodeCount(
				&count,
				size,
			)
			if err == nil && count.More() {
				return nil, ErrFuzzPartial
			}

			return &_Length{
				count: uint64(count.End()),
				more:  count.More(),
			}, err
		},
		encode: func(
			enc *Encoder,
			value *_Length,
		) error {
			var count Count

			return enc.EncodeCount(
				&count,
				value.count,
				size,
			)
		},
	}
}

// FuzzDecodeNext guards review P29-3 for DecodeNext. The first octet picks one of the sizes
// below. The decoder reads the count of the first part, then the length of every part after
// it, and the encoder writes a list of the total, which has the same lengths.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeNext(f *testing.F) {
	sizes := _CountSizes()

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_NextPair(sizes[0]),
		20000,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(4),
		},
		_NextPair(sizes[4]),
		70000,
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
				_NextPair(size),
			)
		},
	)
}

// _NextPair is the pair of FuzzDecodeNext under one size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeNext (review P30)
func _NextPair(size *Constraint) *_Pair[uint64] {
	return &_Pair[uint64]{
		decode: func(dec *Decoder) (uint64, error) {
			return _DecodeParts(
				dec,
				size,
			)
		},
		encode: func(
			enc *Encoder,
			value uint64,
		) error {
			return _EncodeParts(
				enc,
				value,
				size,
			)
		},
	}
}
