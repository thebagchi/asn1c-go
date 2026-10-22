package per

import (
	"testing"
)

// CHECK_FROM_CHARS is a FROM set of 65 ASCII characters: 7 bits in UPER and 8 in APER, and
// its largest value fits, so it keeps its own values. CHECK_MAX_TEXT covers two words and a
// tail. CHECK_BYTE_VALUES is every value of a byte.
const (
	CHECK_FROM_CHARS  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,"
	CHECK_MAX_TEXT    = 17
	CHECK_BYTE_VALUES = 256
)

// HELD_INDEX_CHARS is the FROM set of TestAlphabet_FromIndex, in sorted order, and
// HELD_INDEX_BITS the width X.691 30.5.2 gives four characters.
const (
	HELD_INDEX_CHARS = "ACGT"
	HELD_INDEX_BITS  = 2
)

// CHECK_LONG_SIZES are the texts past CHECK_MAX_TEXT: each side of one AVX2 block, of an
// AVX2 block and an SSE2 block, and of two AVX2 blocks, so each kernel stops and hands
// over at every edge.
var (
	CHECK_LONG_SIZES = []int{
		31,
		32,
		33,
		47,
		48,
		49,
		63,
		64,
		65,
		81,
	}
)

// This file is an internal test because its subject, the fields of _Alphabet, is
// unexported. The external tests cannot read width or compact.

// TestAlphabet_OctetPath guards review P13-5: the octet path needs a width of 8 bits and an
// alphabet that is not compact, so the octet is the character. In the ALIGNED variant
// IA5String, VisibleString and PrintableString keep their own values (X.691 30.5.4 a):
// their largest value is below 2^8). In the UNALIGNED variant they use 7 bits.
//
// Revisions:
//   - 2026-10-20 01:37: initial creation
func TestAlphabet_OctetPath(t *testing.T) {
	kinds := []StringKind{
		STRING_IA5,
		STRING_VISIBLE,
		STRING_PRINTABLE,
	}

	for _, kind := range kinds {
		aligned := ALPHABET_ALIGNED[kind]
		if aligned.bits != BITS_PER_BYTE || aligned.compact {
			t.Fatalf(
				"kind %d aligned: bits %d, compact %t; want %d bits, not compact",
				kind,
				aligned.bits,
				aligned.compact,
				BITS_PER_BYTE,
			)
		}

		unaligned := ALPHABET_UNALIGNED[kind]
		if unaligned.bits == BITS_PER_BYTE {
			t.Fatalf(
				"kind %d unaligned: bits %d; want 7",
				kind,
				unaligned.bits,
			)
		}
	}
}

// TestCheckBytes_MatchesValue guards review P27: _CheckBytes must refuse a text exactly when
// one of its bytes has no value in the alphabet, and return the error _Value gives for the
// first such byte. Each alphabet here takes the octet or the septet path: a range alphabet
// (IA5String, VisibleString), a table (PrintableString), and a FROM set. Every byte value
// goes at every place of texts of 1 to 17 bytes, so a word, its tail, and a lane after a
// carry are all covered. The CHECK_LONG_SIZES texts reach the assembly kernels.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation (review P27)
//   - 2026-10-21 16:08: the texts of CHECK_LONG_SIZES, which reach the kernels (review P28)
//   - 2026-10-21 17:25: the alphabets and the loop moved to _CheckAlphabets, which
//     TestCheckValues_MatchesRune shares
func TestCheckBytes_MatchesValue(t *testing.T) {
	_CheckAlphabets(
		t,
		&_CheckPair{
			check: (*_Alphabet)._CheckBytes,
			want:  _FirstValueError,
		},
	)
}

// TestCheckValues_MatchesRune guards review P29-1: the decoder checks a text it read in one
// pass with _CheckValues, which must refuse it exactly when one byte has no character in the
// alphabet, with the error _Rune gives for the first such byte. The alphabets and the texts
// are those of TestCheckBytes_MatchesValue.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func TestCheckValues_MatchesRune(t *testing.T) {
	_CheckAlphabets(
		t,
		&_CheckPair{
			check: (*_Alphabet)._CheckValues,
			want:  _FirstRuneError,
		},
	)
}

// _CheckPair is a check under test and the reference it must agree with.
type _CheckPair struct {
	check func(
		alphabet *_Alphabet,
		text []byte,
	) error
	want func(
		alphabet *_Alphabet,
		text []byte,
	) error
}

// _CheckAlphabets runs one pair over every alphabet that takes the octet or the septet path.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation, split out of TestCheckBytes_MatchesValue
func _CheckAlphabets(
	t *testing.T,
	pair *_CheckPair,
) {
	t.Helper()

	from, err := NewAlphabet(
		STRING_IA5,
		CHECK_FROM_CHARS,
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		alphabet *_Alphabet
	}{
		{
			name:     "ia5_aligned",
			alphabet: ALPHABET_ALIGNED[STRING_IA5],
		},
		{
			name:     "ia5_unaligned",
			alphabet: ALPHABET_UNALIGNED[STRING_IA5],
		},
		{
			name:     "visible_aligned",
			alphabet: ALPHABET_ALIGNED[STRING_VISIBLE],
		},
		{
			name:     "visible_unaligned",
			alphabet: ALPHABET_UNALIGNED[STRING_VISIBLE],
		},
		{
			name:     "printable_aligned",
			alphabet: ALPHABET_ALIGNED[STRING_PRINTABLE],
		},
		{
			name:     "printable_unaligned",
			alphabet: ALPHABET_UNALIGNED[STRING_PRINTABLE],
		},
		{
			name:     "from_aligned",
			alphabet: from.aligned,
		},
		{
			name:     "from_unaligned",
			alphabet: from.unaligned,
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				_CheckEveryByte(
					t,
					tc.alphabet,
					pair,
				)
			},
		)
	}
}

// _CheckEveryByte puts each byte value at each place of a text of 'A' and compares the
// check of the pair with its reference.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation
//   - 2026-10-21 16:08: the sizes of CHECK_LONG_SIZES too
//   - 2026-10-21 17:25: takes the pair to compare
func _CheckEveryByte(
	t *testing.T,
	alphabet *_Alphabet,
	pair *_CheckPair,
) {
	t.Helper()

	path := alphabet.ascii && !alphabet.compact &&
		(alphabet.bits == BITS_PER_BYTE || alphabet.bits == SEPTET_BITS)
	if !path {
		t.Fatalf(
			"bits %d, compact %t, ascii %t: not on the octet or septet path",
			alphabet.bits,
			alphabet.compact,
			alphabet.ascii,
		)
	}

	sizes := make(
		[]int,
		0,
		CHECK_MAX_TEXT+len(CHECK_LONG_SIZES),
	)
	for size := 1; size <= CHECK_MAX_TEXT; size++ {
		sizes = append(
			sizes,
			size,
		)
	}

	sizes = append(
		sizes,
		CHECK_LONG_SIZES...,
	)

	for _, size := range sizes {
		for place := range size {
			for value := range CHECK_BYTE_VALUES {
				text := make(
					[]byte,
					size,
				)
				for idx := range text {
					text[idx] = 'A'
				}

				text[place] = byte(value)
				_CheckOneText(
					t,
					alphabet,
					pair,
					text,
				)
			}
		}
	}
}

// _CheckOneText compares the check of the pair on one text with its reference.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation
//   - 2026-10-21 17:25: takes the pair to compare
func _CheckOneText(
	t *testing.T,
	alphabet *_Alphabet,
	pair *_CheckPair,
	text []byte,
) {
	t.Helper()

	var (
		want = pair.want(
			alphabet,
			text,
		)
		got = pair.check(
			alphabet,
			text,
		)

		same = (got == nil) == (want == nil)
	)
	if same && got != nil {
		same = got.Error() == want.Error()
	}

	if !same {
		t.Fatalf(
			"text %x: got %v, want %v",
			text,
			got,
			want,
		)
	}
}

// _FirstValueError is the reference: the error of _Value for the first byte that has one.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation
func _FirstValueError(
	alphabet *_Alphabet,
	text []byte,
) error {
	for _, char := range text {
		if _, err := alphabet._Value(rune(char)); err != nil {
			return err
		}
	}

	return nil
}

// _FirstRuneError is the reference of the decoder: the error of _Rune for the first byte
// that has one.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation
func _FirstRuneError(
	alphabet *_Alphabet,
	text []byte,
) error {
	for _, value := range text {
		if _, err := alphabet._Rune(uint64(value)); err != nil {
			return err
		}
	}

	return nil
}

// TestAlphabet_FromIndex guards review P29-3: the alphabet of IA5String (FROM ("ACGT")).
// X.691 30.5.2: four characters need B = 2 bits, and in the ALIGNED variant 2 is already a
// power of two. X.691 30.5.4: the largest value, 0x54, does not fit 2 bits, so each
// character is its index in the sorted set: A 0, C 1, G 2, T 3. The octets of the row are in
// TestHeld_Vectors.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation (review P29-3)
func TestAlphabet_FromIndex(t *testing.T) {
	from, err := NewAlphabet(
		STRING_IA5,
		HELD_INDEX_CHARS,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, alphabet := range []*_Alphabet{
		from.aligned,
		from.unaligned,
	} {
		if alphabet.bits != HELD_INDEX_BITS || !alphabet.compact {
			t.Fatalf(
				"bits %d, compact %t; want %d bits, compact",
				alphabet.bits,
				alphabet.compact,
				HELD_INDEX_BITS,
			)
		}

		for want, char := range HELD_INDEX_CHARS {
			got, err := alphabet._Value(char)
			if err != nil || got != uint64(want) {
				t.Fatalf(
					"%q: index %d, %v; want %d",
					char,
					got,
					err,
					want,
				)
			}
		}
	}
}
