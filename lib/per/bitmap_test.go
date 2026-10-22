package per_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// TestOptionalBitmap_Width checks a root preamble shorter than 64 bits and one
// longer than 64 bits.
//
// The short count is one word. The long count is full words and a remainder
// below 64. Both must match EncodePreamble, in both variants, including after
// a BOOLEAN that shifts the field. The read must return the same words.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func TestOptionalBitmap_Width(t *testing.T) {
	for _, row := range BITMAP_WIDTHS {
		for _, aligned := range []bool{true, false} {
			for _, shift := range []bool{false, true} {
				run := &_BitmapRun{
					name:    row.name + "/" + VARIANT_NAMES[aligned],
					count:   row.count,
					bits:    row.bits,
					aligned: aligned,
					shift:   shift,
				}
				if shift {
					run.name += "/shifted"
				}

				t.Run(
					run.name,
					func(t *testing.T) {
						_OptionalWidth(
							t,
							run,
						)
					},
				)
			}
		}
	}
}

// TestExtensionBitmap_Width checks an additions bitmap shorter than 64 bits
// and one longer than 64 bits.
//
// The short count is normally small, then one word. The long count is the
// large length, then full words and a remainder below 64. Both must match
// EncodeAdditions, and the read must return the same words.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func TestExtensionBitmap_Width(t *testing.T) {
	for _, row := range BITMAP_WIDTHS {
		for _, aligned := range []bool{true, false} {
			run := &_BitmapRun{
				name:    row.name + "/" + VARIANT_NAMES[aligned],
				count:   row.count,
				bits:    row.bits,
				aligned: aligned,
			}

			t.Run(
				run.name,
				func(t *testing.T) {
					_ExtensionWidth(
						t,
						run,
					)
				},
			)
		}
	}
}

// TestExtensionBitmap_UnknownTail checks a bitmap longer than the known 65
// bits. The extra present bit is counted, and it is not stored in the words.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func TestExtensionBitmap_UnknownTail(t *testing.T) {
	const (
		KNOWN = 65
		COUNT = 70
		EXTRA = 69
	)

	for _, aligned := range []bool{true, false} {
		run := &_BitmapRun{
			name:    VARIANT_NAMES[aligned],
			count:   COUNT,
			aligned: aligned,
			bits: []uint64{
				0,
				EXTRA,
			},
		}
		t.Run(
			run.name,
			func(t *testing.T) {
				_UnknownTail(
					t,
					run,
					KNOWN,
				)
			},
		)
	}
}

// TestBitmap_Refusals checks a short word slice and an additions bitmap of no
// bits.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func TestBitmap_Refusals(t *testing.T) {
	var (
		words = per.OptionalBitmap(per.UINT64_BITS + 1)

		err = per.NewAlignedEncoder().WriteOptional(
			words[:1],
			per.UINT64_BITS+1,
		)
	)
	if !errors.Is(
		err,
		per.ErrShortBitString,
	) {
		t.Fatalf(
			"short optional = %v, want ErrShortBitString",
			err,
		)
	}

	err = per.NewAlignedEncoder().WriteExtension(
		nil,
		0,
	)
	if !errors.Is(
		err,
		per.ErrEmptyAdditions,
	) {
		t.Fatalf(
			"empty extension = %v, want ErrEmptyAdditions",
			err,
		)
	}
}

// TestBitmap_SetHas checks the bit order of a word bitmap, X.691 19.2: bit zero
// is the top bit of the first word, and bit 64 is the top bit of the second.
//
// Revisions:
//   - 2026-10-20 14:09: initial creation (review P20)
func TestBitmap_SetHas(t *testing.T) {
	cases := []struct {
		bit  uint64
		word int
		want uint64
	}{
		{
			bit:  0,
			word: 0,
			want: 1 << 63,
		},
		{
			bit:  63,
			word: 0,
			want: 1,
		},
		{
			bit:  64,
			word: 1,
			want: 1 << 63,
		},
		{
			bit:  129,
			word: 2,
			want: 1 << 62,
		},
	}

	for _, tc := range cases {
		words := per.OptionalBitmap(130)
		per.BitmapSet(
			words,
			tc.bit,
		)

		if words[tc.word] != tc.want {
			t.Fatalf(
				"bit %d: word %d = %x, want %x",
				tc.bit,
				tc.word,
				words[tc.word],
				tc.want,
			)
		}

		if !per.BitmapHas(
			words,
			tc.bit,
		) || per.BitmapHas(
			words,
			tc.bit+1,
		) {
			t.Fatalf(
				"BitmapHas(%d) is wrong",
				tc.bit,
			)
		}
	}
}

// BITMAP_WIDTHS is the counts a word bitmap must accept: below 64, exactly 64,
// above 64 with a remainder below 64, and the fragment sizes of 11.9.3.8: an
// additions bitmap from 16384 bits (19.8) and a preamble from 65536 bits (19.3).
var (
	BITMAP_WIDTHS = []_BitmapRun{
		{
			name:  "one",
			count: 1,
			bits: []uint64{
				0,
			},
		},
		{
			name:  "three",
			count: 3,
			bits: []uint64{
				0,
				2,
			},
		},
		{
			name:  "sixty-three",
			count: 63,
			bits: []uint64{
				0,
				62,
			},
		},
		{
			name:  "sixty-four",
			count: 64,
			bits: []uint64{
				0,
				63,
			},
		},
		{
			name:  "sixty-five",
			count: 65,
			bits: []uint64{
				0,
				64,
			},
		},
		{
			name:  "one-thirty",
			count: 130,
			bits: []uint64{
				0,
				64,
				129,
			},
		},
		{
			name:  "sixteen-k",
			count: 16384,
			bits: []uint64{
				0,
				16383,
			},
		},
		{
			name:  "sixteen-k-plus-one",
			count: 16385,
			bits: []uint64{
				0,
				16384,
			},
		},
		{
			name:  "sixty-four-k",
			count: 65536,
			bits: []uint64{
				0,
				65535,
			},
		},
		{
			name:  "seventy-thousand",
			count: 70000,
			bits: []uint64{
				0,
				16384,
				65536,
				69999,
			},
		},
	}
)

// _BitmapRun is one preamble width, the bits that are present, and the variant.
type _BitmapRun struct {
	name    string
	count   uint64
	bits    []uint64
	aligned bool
	shift   bool
}

// _OptionalWidth encodes one width both ways and reads the words back.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func _OptionalWidth(
	t *testing.T,
	run *_BitmapRun,
) {
	t.Helper()

	words := per.OptionalBitmap(run.count)
	if uint64(len(words)) != (run.count+per.UINT64_BITS-1)/per.UINT64_BITS {
		t.Fatalf(
			"OptionalBitmap(%d) has %d words",
			run.count,
			len(words),
		)
	}

	_MarkBitmap(
		words,
		run.bits,
	)

	var (
		got = _EncodeBitmap(
			t,
			run,
			func(enc *per.Encoder) error {
				return enc.WriteOptional(
					words,
					run.count,
				)
			},
		)

		want = _EncodeBitmap(
			t,
			run,
			func(enc *per.Encoder) error {
				return enc.EncodePreamble(_BitmapBits(run))
			},
		)
	)
	if !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"optional %d = %x, preamble %x",
			run.count,
			got,
			want,
		)
	}

	var (
		back = per.OptionalBitmap(run.count)

		dec = DECODERS[run.aligned](got)
	)
	if run.shift {
		if _, err := dec.DecodeBoolean(); err != nil {
			t.Fatalf(
				"DecodeBoolean = %v",
				err,
			)
		}
	}

	if err := dec.ReadOptional(
		back,
		run.count,
	); err != nil {
		t.Fatalf(
			"ReadOptional(%d) = %v",
			run.count,
			err,
		)
	}

	_SameWords(
		t,
		back,
		words,
	)
}

// _ExtensionWidth encodes one additions width both ways and reads it back.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func _ExtensionWidth(
	t *testing.T,
	run *_BitmapRun,
) {
	t.Helper()

	words := per.ExtensionBitmap(run.count)
	_MarkBitmap(
		words,
		run.bits,
	)

	var (
		got = _EncodeBitmap(
			t,
			run,
			func(enc *per.Encoder) error {
				return enc.WriteExtension(
					words,
					run.count,
				)
			},
		)

		want = _EncodeBitmap(
			t,
			run,
			func(enc *per.Encoder) error {
				return enc.EncodeAdditions(_BitmapBits(run))
			},
		)
	)
	if !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"extension %d = %x, additions %x",
			run.count,
			got,
			want,
		)
	}

	var (
		back = per.ExtensionBitmap(run.count)

		_, err = DECODERS[run.aligned](got).ReadExtension(
			back,
			run.count,
		)
	)
	if err != nil {
		t.Fatalf(
			"ReadExtension(%d) = %v",
			run.count,
			err,
		)
	}

	_SameWords(
		t,
		back,
		words,
	)
}

// _UnknownTail encodes count bits and reads only the known prefix.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func _UnknownTail(
	t *testing.T,
	run *_BitmapRun,
	known uint64,
) {
	t.Helper()

	words := per.ExtensionBitmap(run.count)
	_MarkBitmap(
		words,
		run.bits,
	)

	var (
		got = _EncodeBitmap(
			t,
			run,
			func(enc *per.Encoder) error {
				return enc.WriteExtension(
					words,
					run.count,
				)
			},
		)

		back = per.ExtensionBitmap(known)

		unknown, err = DECODERS[run.aligned](got).ReadExtension(
			back,
			known,
		)
	)
	if err != nil {
		t.Fatalf(
			"ReadExtension = %v",
			err,
		)
	}

	if unknown != 1 {
		t.Fatalf(
			"unknown = %d, want 1",
			unknown,
		)
	}

	want := per.ExtensionBitmap(known)
	_MarkBitmap(
		want,
		[]uint64{
			0,
		},
	)
	_SameWords(
		t,
		back,
		want,
	)
}

// _EncodeBitmap runs write on a fresh encoder and returns the octets.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func _EncodeBitmap(
	t *testing.T,
	run *_BitmapRun,
	write func(*per.Encoder) error,
) []byte {
	t.Helper()

	enc := ENCODERS[run.aligned]()
	if run.shift {
		if err := enc.EncodeBoolean(true); err != nil {
			t.Fatalf(
				"EncodeBoolean = %v",
				err,
			)
		}
	}

	if err := write(enc); err != nil {
		t.Fatalf(
			"encode = %v",
			err,
		)
	}

	return enc.Bytes()
}

// _BitmapBits builds the octet bitmap EncodePreamble and EncodeAdditions take.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func _BitmapBits(run *_BitmapRun) *asn1.BitString {
	value := _P7Bits(int(run.count))
	for _, bit := range run.bits {
		_P7Mark(
			value,
			int(bit),
		)
	}

	return value
}

// _MarkBitmap sets each bit in a word bitmap. Bit zero is the top bit of the
// first word.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
//   - 2026-10-20 14:09: sets the bits with BitmapSet, which replaced BitmapPlace (review P20)
func _MarkBitmap(
	words []uint64,
	bits []uint64,
) {
	for _, bit := range bits {
		per.BitmapSet(
			words,
			bit,
		)
	}
}

// _SameWords fails when two word bitmaps differ.
//
// Revisions:
//   - 2026-10-20 13:49: initial creation
func _SameWords(
	t *testing.T,
	got []uint64,
	want []uint64,
) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf(
			"len %d, want %d",
			len(got),
			len(want),
		)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf(
				"word %d = %x, want %x",
				index,
				got[index],
				want[index],
			)
		}
	}
}
