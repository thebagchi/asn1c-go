package per

import (
	"encoding/asn1"
	"testing"
)

// This file is an internal test because the harness reads the codec counts.

// _FuzzSyntax returns an identification of the syntax alternative, which every composite
// type below can carry.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
func _FuzzSyntax() *Identification {
	return &Identification{
		Choices: &Identification_Syntax{2, 1, 1},
	}
}

// _FuzzContext returns an identification of the context-negotiation alternative.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
func _FuzzContext() *Identification {
	return &Identification{
		Choices: &Identification_ContextNegotiation{
			PresentationContextId: 300,
			TransferSyntax:        asn1.ObjectIdentifier{2, 1, 2},
		},
	}
}

// FuzzDecodeIdentification guards review P29-3 for DecodeIdentification.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeIdentification(f *testing.F) {
	pair := &_Pair[*Identification]{
		decode: (*Decoder).DecodeIdentification,
		encode: (*Encoder).EncodeIdentification,
	}

	for _, value := range []*Identification{
		_FuzzSyntax(),
		_FuzzContext(),
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

// FuzzDecodeEmbeddedPDV guards review P29-3 for DecodeEmbeddedPDV.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeEmbeddedPDV(f *testing.F) {
	pair := &_Pair[*EmbeddedPDV]{
		decode: (*Decoder).DecodeEmbeddedPDV,
		encode: (*Encoder).EncodeEmbeddedPDV,
	}

	for _, value := range []*EmbeddedPDV{
		{
			Identification: _FuzzSyntax(),
			DataValue:      []byte{1, 2, 3},
		},
		{
			Identification: _FuzzContext(),
			DataValue:      []byte{},
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

// FuzzDecodeCharacterString guards review P29-3 for DecodeCharacterString.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeCharacterString(f *testing.F) {
	pair := &_Pair[*CharacterString]{
		decode: (*Decoder).DecodeCharacterString,
		encode: (*Encoder).EncodeCharacterString,
	}

	for _, value := range []*CharacterString{
		{
			Identification: _FuzzSyntax(),
			StringValue:    []byte("abc"),
		},
		{
			Identification: _FuzzContext(),
			StringValue:    []byte("hello"),
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

// FuzzDecodeExternal guards review P29-3 for DecodeExternal. The seeds use a syntax with a
// single ASN.1 type, and a context negotiation with a descriptor and an octet aligned value.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeExternal(f *testing.F) {
	var (
		descriptor = "descriptor"
		pair       = &_Pair[*External]{
			decode: (*Decoder).DecodeExternal,
			encode: (*Encoder).EncodeExternal,
		}
	)

	for _, value := range []*External{
		{
			Identification: _FuzzSyntax(),
			Encoding: &ExternalEncoding{
				Choices: &ExternalEncoding_SingleASN1Type{1, 2, 3},
			},
		},
		{
			Identification:      _FuzzContext(),
			DataValueDescriptor: &descriptor,
			Encoding: &ExternalEncoding{
				Choices: &ExternalEncoding_OctetAligned{4, 5},
			},
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

// FuzzDecodeInstanceOf guards review P29-3 for DecodeInstanceOf.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeInstanceOf(f *testing.F) {
	pair := &_Pair[*InstanceOf]{
		decode: (*Decoder).DecodeInstanceOf,
		encode: (*Encoder).EncodeInstanceOf,
	}

	for _, value := range []*InstanceOf{
		{
			TypeID: asn1.ObjectIdentifier{2, 5, 4, 3},
			Value:  []byte{1, 2, 3},
		},
		{
			TypeID: asn1.ObjectIdentifier{1, 3, 6, 1},
			Value: make(
				[]byte,
				300,
			),
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
