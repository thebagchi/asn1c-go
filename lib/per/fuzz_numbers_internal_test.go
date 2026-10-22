package per

import (
	"math"
	"testing"
)

// This file is an internal test because the harness reads the codec counts.

// _Bounds is the lower and the upper bound of a constrained whole number.
type _Bounds struct {
	lb int64
	ub int64
}

// _SameReal reports whether two reals are the same value. Two NaN are the same, and a zero
// differs from a zero of the other sign.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation (review P30)
func _SameReal(
	first,
	second float64,
) bool {
	if math.IsNaN(first) || math.IsNaN(second) {
		return math.IsNaN(first) && math.IsNaN(second)
	}

	return first == second && math.Signbit(first) == math.Signbit(second)
}

// FuzzDecodeConstrainedWholeNumber guards review P29-3 for DecodeConstrainedWholeNumber. The
// first octet picks one of the bounds below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeConstrainedWholeNumber(f *testing.F) {
	bounds := []*_Bounds{
		{
			lb: 0,
			ub: 255,
		},
		{
			lb: -5,
			ub: 70000,
		},
		{
			lb: 7,
			ub: 7,
		},
		{
			lb: math.MinInt64,
			ub: math.MaxInt64,
		},
		{
			lb: 0,
			ub: 1 << 40,
		},
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_ConstrainedWholeNumberPair(bounds[0]),
		200,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(1),
		},
		_ConstrainedWholeNumberPair(bounds[1]),
		1234,
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			pick, rest := _Pick(
				data,
				bounds,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_ConstrainedWholeNumberPair(pick),
			)
		},
	)
}

// _ConstrainedWholeNumberPair is the pair of FuzzDecodeConstrainedWholeNumber under one pair
// of bounds.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeConstrainedWholeNumber
//     (review P30)
func _ConstrainedWholeNumberPair(pick *_Bounds) *_Pair[int64] {
	return &_Pair[int64]{
		decode: func(dec *Decoder) (int64, error) {
			return dec.DecodeConstrainedWholeNumber(
				pick.lb,
				pick.ub,
			)
		},
		encode: func(
			enc *Encoder,
			value int64,
		) error {
			return enc.EncodeConstrainedWholeNumber(
				pick.lb,
				pick.ub,
				value,
			)
		},
	}
}

// FuzzDecodeSemiConstrainedWholeNumber guards review P29-3 for DecodeSemiConstrainedWholeNumber.
// The first octet picks one of the lower bounds below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeSemiConstrainedWholeNumber(f *testing.F) {
	lowers := []int64{
		0,
		-1,
		1000,
		math.MinInt64,
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_SemiConstrainedWholeNumberPair(lowers[0]),
		300,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(1),
		},
		_SemiConstrainedWholeNumberPair(lowers[1]),
		-1,
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			lower, rest := _Pick(
				data,
				lowers,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_SemiConstrainedWholeNumberPair(lower),
			)
		},
	)
}

// _SemiConstrainedWholeNumberPair is the pair of FuzzDecodeSemiConstrainedWholeNumber under
// one lower bound.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of
//     FuzzDecodeSemiConstrainedWholeNumber (review P30)
func _SemiConstrainedWholeNumberPair(lower int64) *_Pair[int64] {
	return &_Pair[int64]{
		decode: func(dec *Decoder) (int64, error) {
			return dec.DecodeSemiConstrainedWholeNumber(lower)
		},
		encode: func(
			enc *Encoder,
			value int64,
		) error {
			return enc.EncodeSemiConstrainedWholeNumber(
				lower,
				value,
			)
		},
	}
}

// FuzzDecodeUnconstrainedWholeNumber guards review P29-3 for DecodeUnconstrainedWholeNumber.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeUnconstrainedWholeNumber(f *testing.F) {
	pair := &_Pair[int64]{
		decode: (*Decoder).DecodeUnconstrainedWholeNumber,
		encode: (*Encoder).EncodeUnconstrainedWholeNumber,
	}

	for _, value := range []int64{
		-129,
		math.MaxInt64,
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

// FuzzDecodeUnsigned guards review P29-3 for DecodeUnsigned. The first octet picks one of the
// constraints below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeUnsigned(f *testing.F) {
	roots := []*UnsignedConstraint{
		nil,
		Unsigned(
			0,
			255,
		),
		SemiUnsigned(7),
		Unsigned(
			0,
			math.MaxUint64,
		),
		Unsigned(
			100,
			70000,
		),
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_UnsignedPair(roots[0]),
		1<<63,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(3),
		},
		_UnsignedPair(roots[3]),
		math.MaxUint64,
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			root, rest := _Pick(
				data,
				roots,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_UnsignedPair(root),
			)
		},
	)
}

// _UnsignedPair is the pair of FuzzDecodeUnsigned under one constraint.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeUnsigned (review P30)
func _UnsignedPair(root *UnsignedConstraint) *_Pair[uint64] {
	return &_Pair[uint64]{
		decode: func(dec *Decoder) (uint64, error) {
			return dec.DecodeUnsigned(root)
		},
		encode: func(
			enc *Encoder,
			value uint64,
		) error {
			return enc.EncodeUnsigned(
				value,
				root,
			)
		},
	}
}

// FuzzDecodeNormallySmallNonNegativeWholeNumber guards review P29-3 for
// DecodeNormallySmallNonNegativeWholeNumber.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeNormallySmallNonNegativeWholeNumber(f *testing.F) {
	pair := &_Pair[uint64]{
		decode: (*Decoder).DecodeNormallySmallNonNegativeWholeNumber,
		encode: (*Encoder).EncodeNormallySmallNonNegativeWholeNumber,
	}

	for _, value := range []uint64{
		5,
		900,
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

// FuzzDecodeEnumerated guards review P29-3 for DecodeEnumerated. The first octet picks one of
// the roots below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeEnumerated(f *testing.F) {
	roots := []*Constraint{
		Constrained(
			0,
			2,
		),
		Constrained(
			0,
			255,
		),
		Constrained(
			0,
			6,
		).Extensible(),
		Constrained(
			0,
			1,
		),
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_EnumeratedPair(roots[0]),
		2,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(2),
		},
		_EnumeratedPair(roots[2]),
		9,
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			root, rest := _Pick(
				data,
				roots,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_EnumeratedPair(root),
			)
		},
	)
}

// _EnumeratedPair is the pair of FuzzDecodeEnumerated under one root.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeEnumerated (review P30)
func _EnumeratedPair(root *Constraint) *_Pair[uint64] {
	return &_Pair[uint64]{
		decode: func(dec *Decoder) (uint64, error) {
			return dec.DecodeEnumerated(root)
		},
		encode: func(
			enc *Encoder,
			value uint64,
		) error {
			return enc.EncodeEnumerated(
				value,
				root,
			)
		},
	}
}

// FuzzDecodeChoiceId guards review P29-3 for DecodeChoiceId. The first octet picks one of the
// roots below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeChoiceId(f *testing.F) {
	roots := []*Constraint{
		Constrained(
			0,
			5,
		),
		Constrained(
			0,
			1,
		),
		Constrained(
			0,
			300,
		),
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
		_ChoiceIdPair(roots[0]),
		4,
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(2),
		},
		_ChoiceIdPair(roots[2]),
		299,
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			root, rest := _Pick(
				data,
				roots,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_ChoiceIdPair(root),
			)
		},
	)
}

// _ChoiceIdPair is the pair of FuzzDecodeChoiceId under one root.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeChoiceId (review P30)
func _ChoiceIdPair(root *Constraint) *_Pair[int64] {
	return &_Pair[int64]{
		decode: func(dec *Decoder) (int64, error) {
			return dec.DecodeChoiceId(root)
		},
		encode: func(
			enc *Encoder,
			value int64,
		) error {
			return enc.EncodeChoiceId(
				value,
				root,
			)
		},
	}
}

// FuzzDecodeChoiceExtensionId guards review P29-3 for DecodeChoiceExtensionId.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeChoiceExtensionId(f *testing.F) {
	pair := &_Pair[int64]{
		decode: (*Decoder).DecodeChoiceExtensionId,
		encode: (*Encoder).EncodeChoiceExtensionId,
	}

	for _, value := range []int64{
		3,
		100,
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

// FuzzDecodeReal guards review P29-3 for DecodeReal. The pair compares with _SameReal, as a
// decoded NaN is not equal to itself.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeReal(f *testing.F) {
	pair := &_Pair[float64]{
		decode: (*Decoder).DecodeReal,
		encode: (*Encoder).EncodeReal,
		equal:  _SameReal,
	}

	for _, value := range []float64{
		1.5,
		-0.0001,
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

// FuzzDecodeNull guards review P29-3 for DecodeNull. A NULL has no value, so the pair carries
// an empty struct and the round trip checks that both sides use no bits.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeNull(f *testing.F) {
	pair := &_Pair[struct{}]{
		decode: func(dec *Decoder) (struct{}, error) {
			return struct{}{}, dec.DecodeNull()
		},
		encode: func(
			enc *Encoder,
			value struct{},
		) error {
			return enc.EncodeNull()
		},
	}

	_FuzzSeedValue(
		f,
		nil,
		pair,
		struct{}{},
	)

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
