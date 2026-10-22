package per_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// ALPHABET_WORKERS is the number of goroutines that share one Alphabet in
// TestAlphabetString_Shared.
const (
	ALPHABET_WORKERS = 8
	ALPHABET_ROUNDS  = 20
)

// TestNewAlphabet_Valid checks the sets that FROM may name. The characters may come in
// any order and with repeats, because a FROM constraint is a set (X.680 clause 51).
// The cases run from one character (B = 0, X.691 clause 30.5.2) to the whole
// alphabet of the type.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestNewAlphabet_Valid(t *testing.T) {
	cases := []struct {
		name  string
		kind  per.StringKind
		chars string
	}{
		{
			name:  "ia5_single",
			kind:  per.STRING_IA5,
			chars: "a",
		},
		{
			name:  "ia5_contiguous",
			kind:  per.STRING_IA5,
			chars: "abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:  "ia5_unordered_with_repeats",
			kind:  per.STRING_IA5,
			chars: "TGCAATTGGCC",
		},
		{
			name:  "ia5_controls",
			kind:  per.STRING_IA5,
			chars: "\x00\x01\x7f",
		},
		{
			name: "visible_all",
			kind: per.STRING_VISIBLE,
			chars: _P5Text(_P5Span(
				32,
				126,
			)),
		},
		{
			name:  "iso646_alias",
			kind:  per.STRING_ISO646,
			chars: "ab",
		},
		{
			name:  "printable_sub",
			kind:  per.STRING_PRINTABLE,
			chars: "09 AZaz",
		},
		{
			name:  "numeric_digits",
			kind:  per.STRING_NUMERIC,
			chars: "0123456789",
		},
		{
			name:  "numeric_all",
			kind:  per.STRING_NUMERIC,
			chars: " 0123456789",
		},
		{
			name:  "bmp_wide",
			kind:  per.STRING_BMP,
			chars: "a\u4e2d\uffff",
		},
		{
			name:  "universal_astral",
			kind:  per.STRING_UNIVERSAL,
			chars: "a\U0001F600\U0010FFFF",
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				alphabet, err := per.NewAlphabet(
					tc.kind,
					tc.chars,
				)
				if err != nil {
					t.Fatalf(
						"NewAlphabet = %v",
						err,
					)
				}

				if alphabet == nil {
					t.Fatalf("NewAlphabet = nil, nil")
				}
			},
		)
	}
}

// _P5Text joins code points into a string.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func _P5Text(list []int) string {
	var text strings.Builder

	for _, code := range list {
		text.WriteRune(rune(code))
	}

	return text.String()
}

// TestNewAlphabet_Refused checks the three ways NewAlphabet says no. A FROM set holds
// characters of the parent type only (X.680 clause 51.7 asks for a subset of the
// parent's alphabet), and X.691 clause 30.1 says an effective permitted alphabet is
// PER-visible for the known-multiplier types only, so the other kinds have no Alphabet.
// An empty set and text that is not UTF-8 name no characters. Each refusal is
// beside a control that works.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestNewAlphabet_Refused(t *testing.T) {
	cases := []struct {
		name  string
		kind  per.StringKind
		chars string
		valid bool
	}{
		{
			name:  "control_ia5",
			kind:  per.STRING_IA5,
			chars: "abc",
			valid: true,
		},
		{
			name:  "ia5_above_127",
			kind:  per.STRING_IA5,
			chars: "ab\u00e9",
		},
		{
			name:  "visible_control_character",
			kind:  per.STRING_VISIBLE,
			chars: "a\x01",
		},
		{
			name:  "visible_delete",
			kind:  per.STRING_VISIBLE,
			chars: "a\x7f",
		},
		{
			name:  "printable_exclamation",
			kind:  per.STRING_PRINTABLE,
			chars: "a!",
		},
		{
			name:  "printable_at_sign",
			kind:  per.STRING_PRINTABLE,
			chars: "a@",
		},
		{
			name:  "numeric_letter",
			kind:  per.STRING_NUMERIC,
			chars: "01a",
		},
		{
			name:  "bmp_astral",
			kind:  per.STRING_BMP,
			chars: "a\U0001F600",
		},
		{
			name:  "empty",
			kind:  per.STRING_IA5,
			chars: "",
		},
		{
			name:  "not_utf8",
			kind:  per.STRING_IA5,
			chars: "a\xffb",
		},
		{
			name:  "utf8_kind",
			kind:  per.STRING_UTF8,
			chars: "ab",
		},
		{
			name:  "general_kind",
			kind:  per.STRING_GENERAL,
			chars: "ab",
		},
		{
			name:  "graphic_kind",
			kind:  per.STRING_GRAPHIC,
			chars: "ab",
		},
		{
			name:  "teletex_kind",
			kind:  per.STRING_TELETEX,
			chars: "ab",
		},
		{
			name:  "t61_kind",
			kind:  per.STRING_T61,
			chars: "ab",
		},
		{
			name:  "videotex_kind",
			kind:  per.STRING_VIDEOTEX,
			chars: "ab",
		},
		{
			name:  "negative_kind",
			kind:  per.StringKind(-1),
			chars: "ab",
		},
		{
			name:  "kind_past_the_end",
			kind:  per.StringKind(1000),
			chars: "ab",
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				alphabet, err := per.NewAlphabet(
					tc.kind,
					tc.chars,
				)

				if tc.valid {
					if err != nil || alphabet == nil {
						t.Fatalf(
							"NewAlphabet = %v, %v, want an alphabet",
							alphabet,
							err,
						)
					}

					return
				}

				if err == nil {
					t.Fatalf("NewAlphabet = nil error, want an error")
				}

				if alphabet != nil {
					t.Errorf(
						"NewAlphabet gave an alphabet and %v",
						err,
					)
				}
			},
		)
	}
}

// TestNewAlphabet_CharacterError checks that the refusal for a character outside the
// parent alphabet is ErrCharacterNotInAlphabet, so that a caller can tell it from the
// refusal for a kind.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestNewAlphabet_CharacterError(t *testing.T) {
	_, err := per.NewAlphabet(
		per.STRING_NUMERIC,
		"01a",
	)
	if !errors.Is(
		err,
		per.ErrCharacterNotInAlphabet,
	) {
		t.Errorf(
			"NewAlphabet = %v, want ErrCharacterNotInAlphabet",
			err,
		)
	}
}

// TestNewAlphabet_OrderAndRepeats checks that the characters of a FROM set carry no
// order and no count (X.680 clause 51: the constraint is a set). Each row of the
// vector file that has a visible FROM and every character of its set in one value
// is built again from the same characters reversed and written twice; the encoding
// must be the oracles' octets.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestNewAlphabet_OrderAndRepeats(t *testing.T) {
	for name := range STRING_KIND_VALUES {
		for _, row := range _P5Rows(
			t,
			name,
		) {
			if row.From == nil || row.FromExt || !strings.HasSuffix(
				row.ID,
				"/nosize/all",
			) {
				continue
			}

			t.Run(
				row.ID,
				func(t *testing.T) {
					_P5CheckShuffled(
						t,
						row,
					)
				},
			)
		}
	}
}

// _P5CheckShuffled builds the alphabet of a row from a reversed, doubled set and checks
// both encodings.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func _P5CheckShuffled(
	t *testing.T,
	row *_P5Row,
) {
	t.Helper()

	reversed := make(
		[]int,
		0,
		2*len(row.From),
	)

	for idx := len(row.From) - 1; idx >= 0; idx-- {
		reversed = append(
			reversed,
			row.From[idx],
		)
	}

	reversed = append(
		reversed,
		row.From...,
	)

	alphabet, err := per.NewAlphabet(
		STRING_KIND_VALUES[row.Kind],
		_P5Text(reversed),
	)
	if err != nil {
		t.Fatalf(
			"NewAlphabet = %v",
			err,
		)
	}

	value := _P5Value(
		t,
		row,
	)

	for _, aligned := range []bool{true, false} {
		enc := ENCODERS[aligned]()

		if err := _P5Encode(
			enc,
			row,
			alphabet,
			value,
		); err != nil {
			t.Fatalf(
				"%s encode = %v",
				VARIANT_NAMES[aligned],
				err,
			)
		}

		_P5Expect(
			t,
			row,
			aligned,
			enc.Bytes(),
		)
	}
}

// TestNewAlphabet_Aliases checks that ISO646String and VisibleString name one
// alphabet (X.680 clause 41, Table 8): the same FROM set encodes the same way.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestNewAlphabet_Aliases(t *testing.T) {
	visible, err := per.NewAlphabet(
		per.STRING_VISIBLE,
		"ACGT",
	)
	if err != nil {
		t.Fatalf(
			"NewAlphabet(visible) = %v",
			err,
		)
	}

	iso, err := per.NewAlphabet(
		per.STRING_ISO646,
		"ACGT",
	)
	if err != nil {
		t.Fatalf(
			"NewAlphabet(iso646) = %v",
			err,
		)
	}

	for _, aligned := range []bool{true, false} {
		var (
			left  = ENCODERS[aligned]()
			right = ENCODERS[aligned]()
		)

		if err := left.EncodeAlphabetString(
			"GATTACA",
			visible,
			per.Constrained(
				1,
				9,
			),
		); err != nil {
			t.Fatalf(
				"encode(visible) = %v",
				err,
			)
		}

		if err := right.EncodeAlphabetString(
			"GATTACA",
			iso,
			per.Constrained(
				1,
				9,
			),
		); err != nil {
			t.Fatalf(
				"encode(iso646) = %v",
				err,
			)
		}

		_Compare(
			t,
			right.Bytes(),
			left.Bytes(),
		)
	}
}

// TestAlphabetString_OutsideCharacter checks that a value with a character that the
// FROM set lacks is refused, on encode. Each case has a control that is in the set.
// The refusal is ErrCharacterNotInAlphabet (X.691 clause 30.5.1: the effective
// permitted alphabet is the only source of characters).
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestAlphabetString_OutsideCharacter(t *testing.T) {
	cases := []struct {
		name    string
		kind    per.StringKind
		chars   string
		inside  string
		outside string
	}{
		{
			name:    "ia5_dna",
			kind:    per.STRING_IA5,
			chars:   "ACGT",
			inside:  "GATTACA",
			outside: "GATTACU",
		},
		{
			name:    "ia5_lowercase_of_set",
			kind:    per.STRING_IA5,
			chars:   "ACGT",
			inside:  "ACGT",
			outside: "acgt",
		},
		{
			name:    "numeric_digits",
			kind:    per.STRING_NUMERIC,
			chars:   "0123",
			inside:  "3210",
			outside: "0124",
		},
		{
			name:    "numeric_space",
			kind:    per.STRING_NUMERIC,
			chars:   "0123",
			inside:  "3210",
			outside: "01 23",
		},
		{
			name:    "printable_pair",
			kind:    per.STRING_PRINTABLE,
			chars:   "01",
			inside:  "0110",
			outside: "0 1",
		},
		{
			name:    "visible_letters",
			kind:    per.STRING_VISIBLE,
			chars:   "abc",
			inside:  "cab",
			outside: "cad",
		},
		{
			name:    "bmp_wide_outside",
			kind:    per.STRING_BMP,
			chars:   "ab",
			inside:  "abba",
			outside: "a\u4e2d",
		},
		{
			name:    "universal_astral_outside",
			kind:    per.STRING_UNIVERSAL,
			chars:   "ab",
			inside:  "abba",
			outside: "a\U0001F600",
		},
	}

	for _, tc := range cases {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					alphabet, err := per.NewAlphabet(
						tc.kind,
						tc.chars,
					)
					if err != nil {
						t.Fatalf(
							"NewAlphabet = %v",
							err,
						)
					}

					if err := ENCODERS[aligned]().EncodeAlphabetString(
						tc.inside,
						alphabet,
						per.Unconstrained(),
					); err != nil {
						t.Fatalf(
							"control encode = %v",
							err,
						)
					}

					err = ENCODERS[aligned]().EncodeAlphabetString(
						tc.outside,
						alphabet,
						per.Unconstrained(),
					)
					if !errors.Is(
						err,
						per.ErrCharacterNotInAlphabet,
					) {
						t.Errorf(
							"encode = %v, want a refused character",
							err,
						)
					}
				},
			)
		}
	}
}

// TestAlphabetString_SizeRefused checks that a value whose length is outside the root
// of its SIZE is refused (X.691 clauses 30.5.6 and 30.5.7 know only lengths inside
// the effective size constraint), and that an extensible SIZE takes the length with the
// extension bit set (30.4).
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestAlphabetString_SizeRefused(t *testing.T) {
	cases := []struct {
		name  string
		size  *per.Constraint
		value string
		valid bool
	}{
		{
			name: "fixed_control",
			size: per.Constrained(
				3,
				3,
			),
			value: "abc",
			valid: true,
		},
		{
			name: "fixed_short",
			size: per.Constrained(
				3,
				3,
			),
			value: "ab",
		},
		{
			name: "fixed_long",
			size: per.Constrained(
				3,
				3,
			),
			value: "abca",
		},
		{
			name: "range_control",
			size: per.Constrained(
				1,
				4,
			),
			value: "abca",
			valid: true,
		},
		{
			name: "range_empty",
			size: per.Constrained(
				1,
				4,
			),
			value: "",
		},
		{
			name: "range_long",
			size: per.Constrained(
				1,
				4,
			),
			value: "abcab",
		},
		{
			name: "extensible_inside",
			size: per.Constrained(
				1,
				4,
			).Extensible(),
			value: "ab",
			valid: true,
		},
		{
			name: "extensible_outside",
			size: per.Constrained(
				1,
				4,
			).Extensible(),
			value: "abcabc",
			valid: true,
		},
		{
			name: "extensible_empty",
			size: per.Constrained(
				1,
				4,
			).Extensible(),
			value: "",
			valid: true,
		},
	}

	for _, tc := range cases {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					alphabet, err := per.NewAlphabet(
						per.STRING_IA5,
						"abc",
					)
					if err != nil {
						t.Fatalf(
							"NewAlphabet = %v",
							err,
						)
					}

					enc := ENCODERS[aligned]()
					err = enc.EncodeAlphabetString(
						tc.value,
						alphabet,
						tc.size,
					)

					if tc.valid != (err == nil) {
						t.Fatalf(
							"encode = %v, want an error: %v",
							err,
							!tc.valid,
						)
					}

					if !tc.valid {
						return
					}

					got, err := DECODERS[aligned](
						enc.Bytes(),
					).DecodeAlphabetString(
						alphabet,
						tc.size,
					)
					if err != nil || got != tc.value {
						t.Fatalf(
							"decode = %q, %v, want %q",
							got,
							err,
							tc.value,
						)
					}
				},
			)
		}
	}
}

// TestAlphabetString_DecodeOutOfRange hands the decoder a character number that the
// alphabet does not have. FROM("abc") has 3 characters and so 2 bits (B = 2, X.691
// clause 30.5.2), and the number 3 is none of them; FROM("abcde") has 5 characters
// and 3 bits unaligned, 4 bits aligned, and the numbers 5 to 7, or 5 to 15, are none
// of them. Each input is the length octet 1 and the bad number (11.9.3.6), and each
// case has a control with the last good number.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestAlphabetString_DecodeOutOfRange(t *testing.T) {
	cases := []struct {
		name    string
		chars   string
		aligned bool
		data    []byte
		valid   bool
	}{
		{
			name:    "abc_aper_control_2",
			chars:   "abc",
			aligned: true,
			data:    []byte{0x01, 0x80},
			valid:   true,
		},
		{
			name:    "abc_aper_3",
			chars:   "abc",
			aligned: true,
			data:    []byte{0x01, 0xC0},
		},
		{
			name:  "abc_uper_control_2",
			chars: "abc",
			data:  []byte{0x01, 0x80},
			valid: true,
		},
		{
			name:  "abc_uper_3",
			chars: "abc",
			data:  []byte{0x01, 0xC0},
		},
		{
			name:    "abcde_aper_control_4",
			chars:   "abcde",
			aligned: true,
			data:    []byte{0x01, 0x40},
			valid:   true,
		},
		{
			name:    "abcde_aper_5",
			chars:   "abcde",
			aligned: true,
			data:    []byte{0x01, 0x50},
		},
		{
			name:    "abcde_aper_15",
			chars:   "abcde",
			aligned: true,
			data:    []byte{0x01, 0xF0},
		},
		{
			name:  "abcde_uper_control_4",
			chars: "abcde",
			data:  []byte{0x01, 0x80},
			valid: true,
		},
		{
			name:  "abcde_uper_5",
			chars: "abcde",
			data:  []byte{0x01, 0xA0},
		},
		{
			name:  "abcde_uper_7",
			chars: "abcde",
			data:  []byte{0x01, 0xE0},
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				alphabet, err := per.NewAlphabet(
					per.STRING_IA5,
					tc.chars,
				)
				if err != nil {
					t.Fatalf(
						"NewAlphabet = %v",
						err,
					)
				}

				_, err = DECODERS[tc.aligned](tc.data).DecodeAlphabetString(
					alphabet,
					per.Unconstrained(),
				)

				if tc.valid && err != nil {
					t.Fatalf(
						"decode = %v, want no error",
						err,
					)
				}

				if !tc.valid && !errors.Is(
					err,
					per.ErrCharacterNotInAlphabet,
				) {
					t.Fatalf(
						"decode = %v, want ErrCharacterNotInAlphabet",
						err,
					)
				}
			},
		)
	}
}

// TestAlphabetString_NilAlphabet checks that a nil *Alphabet is an error and not a
// panic, on both sides.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestAlphabetString_NilAlphabet(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned],
			func(t *testing.T) {
				err := ENCODERS[aligned]().EncodeAlphabetString(
					"a",
					nil,
					per.Unconstrained(),
				)
				if err == nil {
					t.Errorf("encode with a nil alphabet = nil, want an error")
				}

				dec := DECODERS[aligned]([]byte{0x01, 0x00})

				_, err = dec.DecodeAlphabetString(
					nil,
					per.Unconstrained(),
				)
				if err == nil {
					t.Errorf("decode with a nil alphabet = nil, want an error")
				}
			},
		)
	}
}

// TestAlphabetString_Shared checks that one Alphabet is immutable: goroutines encode and
// decode with it at the same time, in both variants, and every result is the
// oracles' answer. The test is for the race detector (make race) as much as for the
// answers. The row is the one of FROM("a".."z") with every character (X.691 clauses
// 30.5.2 and 30.5.4).
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func TestAlphabetString_Shared(t *testing.T) {
	var (
		row = _P5Find(
			t,
			"IA5String",
			"IA5String/fromaz/nosize/all",
		)
		alphabet = _P5Alpha(
			t,
			row,
		)
		value = _P5Value(
			t,
			row,
		)
	)

	var group sync.WaitGroup

	failures := make(
		chan string,
		ALPHABET_WORKERS*ALPHABET_ROUNDS*2,
	)

	for range ALPHABET_WORKERS {
		group.Add(1)

		go func() {
			defer group.Done()

			for range ALPHABET_ROUNDS {
				for _, aligned := range []bool{true, false} {
					failures <- _P5Round(
						row,
						alphabet,
						value,
						aligned,
					)
				}
			}
		}()
	}

	group.Wait()
	close(failures)

	for failure := range failures {
		if failure != "" {
			t.Error(failure)
		}
	}
}

// _P5Round encodes and decodes the value of a row once with a shared Alphabet and gives
// the text of the first problem, or an empty string. It does not call t, because it
// runs in a goroutine.
//
// Revisions:
//   - 2026-10-19 12:47: initial creation
func _P5Round(
	row *_P5Row,
	alphabet *per.Alphabet,
	value string,
	aligned bool,
) string {
	enc := ENCODERS[aligned]()

	if err := _P5Encode(
		enc,
		row,
		alphabet,
		value,
	); err != nil {
		return err.Error()
	}

	want := _Both(
		row.Aper,
		row.Uper,
	)[aligned]
	if want == "" {
		return "the row has no octets"
	}

	if got := _P5Hex(enc.Bytes()); got != want {
		return VARIANT_NAMES[aligned] + " encoded " + got + ", want " + want
	}

	got, err := _P5Decode(
		DECODERS[aligned](enc.Bytes()),
		row,
		alphabet,
	)
	if err != nil {
		return err.Error()
	}

	if got != value {
		return VARIANT_NAMES[aligned] + " decoded a different value"
	}

	return ""
}
