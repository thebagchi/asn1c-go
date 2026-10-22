package per

import (
	"encoding/asn1"
	"testing"
)

// This file is an internal test because the harness reads the codec counts.

// _Letters is a permitted alphabet and the size of the string that it spells.
type _Letters struct {
	alphabet *Alphabet
	size     *Constraint
}

// _Text is a restricted string kind and the size of its value.
type _Text struct {
	kind StringKind
	size *Constraint
}

// _FuzzAlphabet returns the permitted alphabet of chars for a kind, or fails the fuzz function
// when the kind does not take it.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
func _FuzzAlphabet(
	f *testing.F,
	kind StringKind,
	chars string,
) *Alphabet {
	f.Helper()

	alphabet, err := NewAlphabet(
		kind,
		chars,
	)
	if err != nil {
		f.Fatalf(
			"alphabet %q: %v",
			chars,
			err,
		)
	}

	return alphabet
}

// FuzzDecodeAlphabetString guards review P29-3 for DecodeAlphabetString. The first octet picks
// one of the alphabets and sizes below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeAlphabetString(f *testing.F) {
	letters := []*_Letters{
		{
			alphabet: _FuzzAlphabet(
				f,
				STRING_IA5,
				"abc",
			),
			size: Unconstrained(),
		},
		{
			alphabet: _FuzzAlphabet(
				f,
				STRING_PRINTABLE,
				"0123456789",
			),
			size: Constrained(
				1,
				10,
			),
		},
		{
			alphabet: _FuzzAlphabet(
				f,
				STRING_NUMERIC,
				"0123",
			),
			size: Constrained(
				4,
				4,
			),
		},
		{
			alphabet: _FuzzAlphabet(
				f,
				STRING_VISIBLE,
				"ABCDEFGH",
			),
			size: Constrained(
				0,
				20,
			).Extensible(),
		},
		{
			alphabet: _FuzzAlphabet(
				f,
				STRING_BMP,
				"abcdef",
			),
			size: Constrained(
				0,
				70000,
			),
		},
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_AlphabetStringPair(letters[0]),
		"abcabc",
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(2),
		},
		_AlphabetStringPair(letters[2]),
		"0123",
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			pick, rest := _Pick(
				data,
				letters,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_AlphabetStringPair(pick),
			)
		},
	)
}

// _AlphabetStringPair is the pair of FuzzDecodeAlphabetString under one alphabet and size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeAlphabetString (review P30)
func _AlphabetStringPair(pick *_Letters) *_Pair[string] {
	return &_Pair[string]{
		decode: func(dec *Decoder) (string, error) {
			return dec.DecodeAlphabetString(
				pick.alphabet,
				pick.size,
			)
		},
		encode: func(
			enc *Encoder,
			value string,
		) error {
			return enc.EncodeAlphabetString(
				value,
				pick.alphabet,
				pick.size,
			)
		},
	}
}

// FuzzDecodeRestrictedString guards review P29-3 for DecodeRestrictedString. The first octet
// picks one of the kinds and sizes below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeRestrictedString(f *testing.F) {
	texts := []*_Text{
		{
			kind: STRING_UTF8,
			size: Unconstrained(),
		},
		{
			kind: STRING_IA5,
			size: Constrained(
				1,
				10,
			),
		},
		{
			kind: STRING_VISIBLE,
			size: Unconstrained(),
		},
		{
			kind: STRING_PRINTABLE,
			size: Constrained(
				0,
				20,
			).Extensible(),
		},
		{
			kind: STRING_NUMERIC,
			size: Constrained(
				4,
				4,
			),
		},
		{
			kind: STRING_BMP,
			size: Constrained(
				0,
				70000,
			),
		},
	}

	_FuzzSeedValue(
		f,
		[]byte{
			byte(1),
		},
		_RestrictedStringPair(texts[1]),
		"hello",
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(0),
		},
		_RestrictedStringPair(texts[0]),
		"héllo",
	)

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			pick, rest := _Pick(
				data,
				texts,
			)

			_FuzzRoundTrip(
				t,
				rest,
				_RestrictedStringPair(pick),
			)
		},
	)
}

// _RestrictedStringPair is the pair of FuzzDecodeRestrictedString under one kind and size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeRestrictedString (review P30)
func _RestrictedStringPair(pick *_Text) *_Pair[string] {
	return &_Pair[string]{
		decode: func(dec *Decoder) (string, error) {
			return dec.DecodeRestrictedString(
				pick.kind,
				pick.size,
			)
		},
		encode: func(
			enc *Encoder,
			value string,
		) error {
			return enc.EncodeRestrictedString(
				value,
				pick.kind,
				pick.size,
			)
		},
	}
}

// FuzzDecodeOctetString guards review P29-3 for DecodeOctetString. The first octet picks one of
// the sizes below, and the decoder reads the rest.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeOctetString(f *testing.F) {
	sizes := []*Constraint{
		Unconstrained(),
		Constrained(
			0,
			255,
		),
		Constrained(
			4,
			4,
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
		_OctetStringPair(sizes[0]),
		[]byte{1, 2, 3},
	)
	_FuzzSeedValue(
		f,
		[]byte{
			byte(3),
		},
		_OctetStringPair(sizes[3]),
		[]byte{9, 8, 7, 6, 5},
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
				_OctetStringPair(size),
			)
		},
	)
}

// _OctetStringPair is the pair of FuzzDecodeOctetString under one size.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation, split out of FuzzDecodeOctetString (review P30)
func _OctetStringPair(size *Constraint) *_Pair[[]byte] {
	return &_Pair[[]byte]{
		decode: func(dec *Decoder) ([]byte, error) {
			return dec.DecodeOctetString(size)
		},
		encode: func(
			enc *Encoder,
			value []byte,
		) error {
			return enc.EncodeOctetString(
				value,
				size,
			)
		},
	}
}

// FuzzDecodeIRI guards review P29-3 for DecodeIRI.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeIRI(f *testing.F) {
	pair := &_Pair[string]{
		decode: (*Decoder).DecodeIRI,
		encode: (*Encoder).EncodeIRI,
	}

	for _, value := range []string{
		"/ISO/Registration-Procedure",
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

// FuzzDecodeRelativeIRI guards review P29-3 for DecodeRelativeIRI.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeRelativeIRI(f *testing.F) {
	pair := &_Pair[string]{
		decode: (*Decoder).DecodeRelativeIRI,
		encode: (*Encoder).EncodeRelativeIRI,
	}

	for _, value := range []string{
		"Registration-Procedure/3",
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

// FuzzDecodeObjectIdentifier guards review P29-3 for DecodeObjectIdentifier.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeObjectIdentifier(f *testing.F) {
	pair := &_Pair[asn1.ObjectIdentifier]{
		decode: (*Decoder).DecodeObjectIdentifier,
		encode: (*Encoder).EncodeObjectIdentifier,
	}

	for _, value := range []asn1.ObjectIdentifier{
		{2, 5, 4, 3},
		{1, 3, 6, 1, 4, 1, 311, 21},
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

// FuzzDecodeRelativeOID guards review P29-3 for DecodeRelativeOID.
//
// Revisions:
//   - 2026-10-21 18:51: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeRelativeOID(f *testing.F) {
	pair := &_Pair[[]int]{
		decode: (*Decoder).DecodeRelativeOID,
		encode: (*Encoder).EncodeRelativeOID,
	}

	for _, value := range [][]int{
		{8571, 3, 2},
		{0},
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
