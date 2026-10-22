package bitbuffer_test

import (
	"bytes"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// PEEL_PATTERNS are the field values of TestRegression_P24PeelMatchesBits: every bit set,
// alternating bits, and a pattern with no period inside a word.
var (
	PEEL_PATTERNS = []uint64{
		^uint64(0),
		0xAAAAAAAAAAAAAAAA,
		0x0123456789ABCDEF,
	}
)

// TestRegression_P24PeelMatchesBits guards review P24: a field that starts inside a byte and
// does not fit in it fills that byte, then the rest goes out as whole bytes. The octets must
// be the bits of a writer that appends one bit at a time, most significant first, at every
// offset from 1 to 7 and every width from 1 to 64, with a second field after the first. The
// two fields must read back.
//
// Revisions:
//   - 2026-10-21 09:44: initial creation (review P24)
func TestRegression_P24PeelMatchesBits(t *testing.T) {
	for offset := uint8(1); offset < bitbuffer.BITS_PER_BYTE; offset++ {
		for width := uint8(1); width <= bitbuffer.UINT64_BITS; width++ {
			for _, pattern := range PEEL_PATTERNS {
				_CheckPeel(
					t,
					offset,
					width,
					pattern,
				)
			}
		}
	}
}

// _CheckPeel writes an offset, a field of width bits and a 13-bit trailer, compares the octets
// with the bit-at-a-time reference, and reads the three fields back.
//
// Revisions:
//   - 2026-10-21 09:44: initial creation (review P24)
func _CheckPeel(
	t *testing.T,
	offset uint8,
	width uint8,
	pattern uint64,
) {
	t.Helper()

	const (
		TRAILER_BITS = 13
		TRAILER      = 0x1A5B
	)

	var (
		fields = []*_PeelField{
			{
				width: offset,
				value: pattern >> 3,
			},
			{
				width: width,
				value: pattern,
			},
			{
				width: TRAILER_BITS,
				value: TRAILER,
			},
		}

		codec     = bitbuffer.CreateWriter()
		reference = &_BitWriter{}
	)

	for _, field := range fields {
		field.value &= ^uint64(0) >> (bitbuffer.UINT64_BITS - field.width)

		if err := codec.Write(
			field.width,
			field.value,
		); err != nil {
			t.Fatal(err)
		}

		reference._Append(field)
	}

	got := codec.Bytes()
	if !bytes.Equal(
		got,
		reference.octets,
	) {
		t.Fatalf(
			"offset %d width %d: %x, want %x",
			offset,
			width,
			got,
			reference.octets,
		)
	}

	_ReadPeel(
		t,
		got,
		fields,
	)
}

// _ReadPeel reads the fields of _CheckPeel back from octets.
//
// Revisions:
//   - 2026-10-21 09:44: initial creation (review P24)
func _ReadPeel(
	t *testing.T,
	octets []byte,
	fields []*_PeelField,
) {
	t.Helper()

	reader := bitbuffer.CreateReader(octets)
	for _, field := range fields {
		value, err := reader.Read(field.width)
		if err != nil || value != field.value {
			t.Fatalf(
				"read %d bits = %x, %v; want %x",
				field.width,
				value,
				err,
				field.value,
			)
		}
	}
}

// _PeelField is one field of _CheckPeel: its width and its value.
type _PeelField struct {
	width uint8
	value uint64
}

// _BitWriter appends bits one at a time, most significant first: the reference of
// TestRegression_P24PeelMatchesBits.
type _BitWriter struct {
	octets []byte
	bits   uint64
}

// _Append appends the width bits of a field, the most significant bit first.
//
// Revisions:
//   - 2026-10-21 09:44: initial creation (review P24)
func (w *_BitWriter) _Append(field *_PeelField) {
	for index := int(field.width) - 1; index >= 0; index-- {
		if w.bits%bitbuffer.BITS_PER_BYTE == 0 {
			w.octets = append(
				w.octets,
				0,
			)
		}

		if field.value>>uint(index)&1 == 1 {
			shift := bitbuffer.BITS_PER_BYTE - 1 - w.bits%bitbuffer.BITS_PER_BYTE
			w.octets[len(w.octets)-1] |= 1 << shift
		}

		w.bits++
	}
}
