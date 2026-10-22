package per_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_STRINGS is the kind key in testing.json of testing/strings.py, which asks pycrate 0.8.1
// and
// Erlang/OTP 29.1.1 for the APER and UPER octets of every row. Where the two answer
// differently the file keeps both and names the oracle that X.691 supports (the
// "disagreement" field, and the "faults" list at the top of the file).
//
// A row holds its value as a list of characters ("chars") or as a rule ("gen"); the
// rules are the ones of the header of strings.py. A row keeps its octets in hex, or
// the sha256 and the length in octets of each encoding when they are long.
const (
	VECTOR_STRINGS = "strings"
)

// The names of the value rules and of the alphabets of strings.py.
const (
	RULE_ALL    = "all"
	RULE_REV    = "rev"
	RULE_CYCLE  = "cycle"
	RULE_STRIDE = "stride"
	RULE_PAD    = "pad"

	DESCRIBE_LIMIT = 24
	CYCLE_MUL      = 31
	CYCLE_ADD      = 3

	SURROGATE_LOW  = 0xD800
	SURROGATE_HIGH = 0xDFFF
	PAD_CHAR       = 'a'

	IA5_LAST      = 127
	IA5X_LAST     = 126
	VISIBLE_LOW   = 32
	VISIBLE_HIGH  = 126
	OCTET_LAST    = 255
	BMP_LAST      = 0xFFFF
	NUMERIC_SET   = " 0123456789"
	PRINTABLE_SET = " '()+,-./0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz"
)

// STRING_KIND_VALUES maps the type names of testing.json (strings) to the kinds of the package.
// The first spelling of two types of the same kind is an alias (X.680 clause 41,
// Table 8): ISO646String is VisibleString, and T61String is TeletexString.
var (
	STRING_KIND_VALUES = map[string]per.StringKind{
		"BMPString":       per.STRING_BMP,
		"GeneralString":   per.STRING_GENERAL,
		"GraphicString":   per.STRING_GRAPHIC,
		"IA5String":       per.STRING_IA5,
		"ISO646String":    per.STRING_ISO646,
		"NumericString":   per.STRING_NUMERIC,
		"PrintableString": per.STRING_PRINTABLE,
		"TeletexString":   per.STRING_TELETEX,
		"T61String":       per.STRING_T61,
		"UniversalString": per.STRING_UNIVERSAL,
		"UTF8String":      per.STRING_UTF8,
		"VideotexString":  per.STRING_VIDEOTEX,
		"VisibleString":   per.STRING_VISIBLE,
	}

	// STRING_BYTE_KINDS are the types of X.691 clause 30.6 whose Go string carries
	// the octets as they are, with no transcoding: the ISO 2022 escape sequences of
	// these types, if any, are the caller's. A character of a row is one octet.
	STRING_BYTE_KINDS = map[string]bool{
		"GeneralString":  true,
		"GraphicString":  true,
		"TeletexString":  true,
		"T61String":      true,
		"VideotexString": true,
	}
)

// UTF8_MIX is the alphabet "utf8" of strings.py: characters of one to four octets.
var (
	UTF8_MIX = []int{
		0x41,
		0x7A,
		0xE9,
		0x20AC,
		0x4E2D,
		0x1F600,
		0x10FFFF,
		0x7FF,
		0x800,
		0xFFFD,
		0x10000,
		0x80,
	}
)

type _P5Size struct {
	Lb  int64  `json:"lb"`
	Ub  *int64 `json:"ub"`
	Ext bool   `json:"ext"`
}

type _P5Gen struct {
	Rule  string `json:"rule"`
	Over  string `json:"over"`
	Count int    `json:"count"`
	Step  int    `json:"step"`
	Tail  []int  `json:"tail"`
}

// _P5Pair holds the answers of both oracles for one variant: pycrate ("py") and Erlang ("er").
// An answer is hex text, {sha256, octets} or null, so it stays raw.
type _P5Pair struct {
	Py json.RawMessage `json:"py"`
	Er json.RawMessage `json:"er"`
}

// _P5Oracles holds the answers of both oracles for both variants.
type _P5Oracles struct {
	Aper *_P5Pair `json:"aper"`
	Uper *_P5Pair `json:"uper"`
}

// _P5Row is one value of one type of testing.json (strings).
type _P5Row struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	Size       *_P5Size    `json:"size"`
	From       []int       `json:"from"`
	FromExt    bool        `json:"from_ext"`
	Chars      []int       `json:"chars"`
	Gen        *_P5Gen     `json:"gen"`
	Length     int         `json:"length"`
	Oracles    *_P5Oracles `json:"answers"`
	Agree      bool        `json:"agree"`
	Aper       string      `json:"aper"`
	Uper       string      `json:"uper"`
	AperSha256 string      `json:"aper_sha256"`
	UperSha256 string      `json:"uper_sha256"`
	AperOctets int         `json:"aper_octets"`
	UperOctets int         `json:"uper_octets"`
}

type _P5File struct {
	Strings []*_P5Row `json:"strings"`
}

// STRING_ROWS holds the rows of testing.json (strings) by type name. The file is read once
// for the whole run.
var (
	STRING_ROWS      map[string][]*_P5Row
	STRING_ONCE      sync.Once
	STRING_ALPHABETS sync.Map
)

// _P5Rows returns the rows of one type.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Rows(
	t *testing.T,
	kind string,
) []*_P5Row {
	t.Helper()

	STRING_ONCE.Do(func() {
		var file _P5File

		_Load(
			t,
			VECTOR_STRINGS,
			&file,
		)

		STRING_ROWS = make(map[string][]*_P5Row)

		for _, row := range file.Strings {
			STRING_ROWS[row.Kind] = append(
				STRING_ROWS[row.Kind],
				row,
			)
		}
	})

	if len(STRING_ROWS[kind]) == 0 {
		t.Fatalf(
			"no rows for %s in %s",
			kind,
			VECTOR_STRINGS,
		)
	}

	return STRING_ROWS[kind]
}

// _P5Alphabet returns the characters of the alphabet a rule runs over, in ascending
// order. The same list is in testing/strings.py.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Alphabet(name string) []int {
	if cached, ok := STRING_ALPHABETS.Load(name); ok {
		return cached.([]int)
	}

	list := _P5Build(name)
	STRING_ALPHABETS.Store(
		name,
		list,
	)

	return list
}

// _P5Build lists one alphabet.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Build(name string) []int {
	switch name {
	case "ia5", "ascii":
		return _P5Span(
			0,
			IA5_LAST,
		)
	case "ia5x":
		return _P5Span(
			0,
			IA5X_LAST,
		)
	case "visible":
		return _P5Span(
			VISIBLE_LOW,
			VISIBLE_HIGH,
		)
	case "octets":
		return _P5Span(
			0,
			OCTET_LAST,
		)
	case "printable":
		return _P5Sorted(PRINTABLE_SET)
	case "numeric":
		return _P5Sorted(NUMERIC_SET)
	case "bmp":
		return _P5Scalars(BMP_LAST)
	case "universal":
		return _P5Scalars(utf8.MaxRune)
	case "utf8":
		return _P5SortList(UTF8_MIX)
	}

	panic("unknown alphabet " + name)
}

// _P5Span lists the integers from low to high.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Span(
	low,
	high int,
) []int {
	list := make(
		[]int,
		0,
		high-low+1,
	)

	for code := low; code <= high; code++ {
		list = append(
			list,
			code,
		)
	}

	return list
}

// _P5Scalars lists every Unicode scalar value up to high: the characters that a Go
// string can carry. A surrogate is not one of them.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Scalars(high int) []int {
	list := make(
		[]int,
		0,
		high+1,
	)

	for code := 0; code <= high; code++ {
		if code >= SURROGATE_LOW && code <= SURROGATE_HIGH {
			continue
		}

		list = append(
			list,
			code,
		)
	}

	return list
}

// _P5Sorted lists the characters of text in ascending order.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Sorted(text string) []int {
	list := make(
		[]int,
		0,
		len(text),
	)

	for _, char := range text {
		list = append(
			list,
			int(char),
		)
	}

	return _P5SortList(list)
}

// _P5SortList returns a sorted copy of list.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5SortList(list []int) []int {
	out := append(
		[]int(nil),
		list...,
	)

	sort.Ints(out)

	return out
}

// _P5Chars returns the characters of a row as code points: the list of the row, or
// the result of its rule.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Chars(
	t *testing.T,
	row *_P5Row,
) []int {
	t.Helper()

	if row.Gen == nil {
		return row.Chars
	}

	if row.Gen.Rule == RULE_PAD {
		list := make(
			[]int,
			0,
			row.Gen.Count+len(row.Gen.Tail),
		)

		for range row.Gen.Count {
			list = append(
				list,
				PAD_CHAR,
			)
		}

		return append(
			list,
			row.Gen.Tail...,
		)
	}

	base := _P5Alphabet(row.Gen.Over)
	if row.From != nil {
		base = _P5Keep(
			base,
			row.From,
		)
	}

	list := _P5Apply(
		t,
		row.Gen,
		base,
	)

	if len(list) != row.Length {
		t.Fatalf(
			"%s: rule gives %d characters, want %d",
			row.ID,
			len(list),
			row.Length,
		)
	}

	return list
}

// _P5Keep keeps the characters of base that are in set.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Keep(
	base,
	set []int,
) []int {
	keep := make(
		map[int]bool,
		len(set),
	)

	for _, code := range set {
		keep[code] = true
	}

	out := make(
		[]int,
		0,
		len(set),
	)

	for _, code := range base {
		if keep[code] {
			out = append(
				out,
				code,
			)
		}
	}

	return out
}

// _P5Apply runs one value rule over an alphabet.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Apply(
	t *testing.T,
	gen *_P5Gen,
	base []int,
) []int {
	t.Helper()

	switch gen.Rule {
	case RULE_ALL:
		return base
	case RULE_REV:
		out := make(
			[]int,
			0,
			len(base),
		)

		for idx := len(base) - 1; idx >= 0; idx-- {
			out = append(
				out,
				base[idx],
			)
		}

		return out
	case RULE_CYCLE:
		return _P5Pick(
			base,
			gen.Count,
			CYCLE_MUL,
			CYCLE_ADD,
		)
	case RULE_STRIDE:
		return _P5Pick(
			base,
			gen.Count,
			gen.Step,
			0,
		)
	}

	t.Fatalf(
		"unknown rule %q",
		gen.Rule,
	)

	return nil
}

// _P5Pick returns count characters: character i is base[(i*mul+add) mod len(base)].
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Pick(
	base []int,
	count,
	mul,
	add int,
) []int {
	out := make(
		[]int,
		count,
	)

	for idx := range out {
		out[idx] = base[(idx*mul+add)%len(base)]
	}

	return out
}

// _P5Value returns the Go string of a row. A character of a byte type is one octet;
// any other is a rune.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Value(
	t *testing.T,
	row *_P5Row,
) string {
	t.Helper()

	chars := _P5Chars(
		t,
		row,
	)

	if STRING_BYTE_KINDS[row.Kind] {
		octets := make(
			[]byte,
			len(chars),
		)

		for idx, code := range chars {
			octets[idx] = byte(code)
		}

		return string(octets)
	}

	var text bytes.Buffer

	for _, code := range chars {
		text.WriteRune(rune(code))
	}

	return text.String()
}

// _P5Constraint builds the SIZE constraint a row describes.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Constraint(size *_P5Size) *per.Constraint {
	if size == nil {
		return per.Unconstrained()
	}

	var built *per.Constraint

	if size.Ub == nil {
		built = per.SemiConstrained(size.Lb)
	} else {
		built = per.Constrained(
			size.Lb,
			*size.Ub,
		)
	}

	if size.Ext {
		return built.Extensible()
	}

	return built
}

// _P5Alpha builds the Alphabet of a row that has a visible FROM, and gives nil for a
// row with none. An extensible FROM is not PER-visible (X.691 clause 10.3.11), so
// that row is encoded with the parent kind.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Alpha(
	t *testing.T,
	row *_P5Row,
) *per.Alphabet {
	t.Helper()

	if row.From == nil || row.FromExt {
		return nil
	}

	var text bytes.Buffer

	for _, code := range row.From {
		text.WriteRune(rune(code))
	}

	alphabet, err := per.NewAlphabet(
		STRING_KIND_VALUES[row.Kind],
		text.String(),
	)
	if err != nil {
		t.Fatalf(
			"%s: NewAlphabet = %v",
			row.ID,
			err,
		)
	}

	return alphabet
}

// _P5Encode writes the value of a row with the call its type needs.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Encode(
	enc *per.Encoder,
	row *_P5Row,
	alphabet *per.Alphabet,
	value string,
) error {
	if alphabet != nil {
		return enc.EncodeAlphabetString(
			value,
			alphabet,
			_P5Constraint(row.Size),
		)
	}

	return enc.EncodeRestrictedString(
		value,
		STRING_KIND_VALUES[row.Kind],
		_P5Constraint(row.Size),
	)
}

// _P5Decode reads the value of a row with the call its type needs.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Decode(
	dec *per.Decoder,
	row *_P5Row,
	alphabet *per.Alphabet,
) (string, error) {
	if alphabet != nil {
		return dec.DecodeAlphabetString(
			alphabet,
			_P5Constraint(row.Size),
		)
	}

	return dec.DecodeRestrictedString(
		STRING_KIND_VALUES[row.Kind],
		_P5Constraint(row.Size),
	)
}

// _P5Expect compares an encoding with the oracles' answer for a row and returns the
// octets that the decode step reads. A short row keeps its octets, so those are the
// answer. A long row keeps the sha256 and the length, so the octets are the ones
// just written, which the digest has already proved to be the oracles' answer.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Expect(
	t *testing.T,
	row *_P5Row,
	aligned bool,
	got []byte,
) []byte {
	t.Helper()

	var (
		hexed = _Both(
			row.Aper,
			row.Uper,
		)[aligned]
		digest = _Both(
			row.AperSha256,
			row.UperSha256,
		)[aligned]
		octets = map[bool]int{
			true:  row.AperOctets,
			false: row.UperOctets,
		}[aligned]
	)

	if digest == "" {
		want := _Unhex(
			t,
			hexed,
		)

		_Compare(
			t,
			got,
			want,
		)

		return want
	}

	if len(got) != octets {
		t.Fatalf(
			"encoded %d octets, want %d",
			len(got),
			octets,
		)
	}

	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != digest {
		t.Fatalf(
			"sha256 of the %d encoded octets differs from the oracles'",
			len(got),
		)
	}

	return got
}

// _P5Describe shortens a value for a failure message.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Describe(value string) string {
	if len(value) <= DESCRIBE_LIMIT {
		return fmt.Sprintf(
			"%q",
			value,
		)
	}

	return fmt.Sprintf(
		"%q... (%d octets)",
		value[:DESCRIBE_LIMIT],
		len(value),
	)
}

// _P5Visible keeps the rows whose constraints are all PER-visible. _P5Hidden keeps the
// rows with an extensible FROM, which X.691 clause 10.3.11 does not make visible.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Visible(row *_P5Row) bool {
	return !row.FromExt
}

// _P5Hidden is the other half of _P5Visible.
//
// Revisions:
//   - 2026-10-19 12:49: initial creation
func _P5Hidden(row *_P5Row) bool {
	return row.FromExt
}

// _P5Vectors checks every row of one type, in both variants: the encoding equals the
// oracles' octets, and decoding those octets gives the value back. A row with a
// visible FROM goes through NewAlphabet and the alphabet calls, one Alphabet for both
// variants; any other row, and a row whose FROM is extensible, goes through
// EncodeRestrictedString.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Vectors(
	t *testing.T,
	kind string,
	keep func(row *_P5Row) bool,
) {
	t.Helper()

	for _, row := range _P5Rows(
		t,
		kind,
	) {
		if !keep(row) {
			continue
		}

		t.Run(
			row.ID,
			func(t *testing.T) {
				alphabet := _P5Alpha(
					t,
					row,
				)

				for _, aligned := range []bool{true, false} {
					t.Run(
						VARIANT_NAMES[aligned],
						func(t *testing.T) {
							_P5CheckRow(
								t,
								aligned,
								row,
								alphabet,
							)
						},
					)
				}
			},
		)
	}
}

// _P5CheckRow encodes the value of a row, compares it with the oracles' octets, and
// decodes those octets.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5CheckRow(
	t *testing.T,
	aligned bool,
	row *_P5Row,
	alphabet *per.Alphabet,
) {
	t.Helper()

	var (
		value = _P5Value(
			t,
			row,
		)
		enc = ENCODERS[aligned]()
	)

	if err := _P5Encode(
		enc,
		row,
		alphabet,
		value,
	); err != nil {
		t.Fatalf(
			"encode %s = %v",
			_P5Describe(value),
			err,
		)
	}

	var (
		want = _P5Expect(
			t,
			row,
			aligned,
			enc.Bytes(),
		)

		got, err = _P5Decode(
			DECODERS[aligned](want),
			row,
			alphabet,
		)
	)
	if err != nil {
		t.Fatalf(
			"decode = %v",
			err,
		)
	}

	if got != value {
		t.Fatalf(
			"decode = %s, want %s",
			_P5Describe(got),
			_P5Describe(value),
		)
	}
}

// _P5Framed writes every value of one type between BOOLEAN fields and reads it back,
// in both variants. A decoder that stops a bit early or late, or skips the wrong
// padding, reads a wrong BOOLEAN.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5Framed(
	t *testing.T,
	kind string,
	keep func(row *_P5Row) bool,
) {
	t.Helper()

	for _, row := range _P5Rows(
		t,
		kind,
	) {
		if !keep(row) {
			continue
		}

		t.Run(
			row.ID,
			func(t *testing.T) {
				alphabet := _P5Alpha(
					t,
					row,
				)

				for _, aligned := range []bool{true, false} {
					t.Run(
						VARIANT_NAMES[aligned],
						func(t *testing.T) {
							_P5CheckFramed(
								t,
								aligned,
								row,
								alphabet,
							)
						},
					)
				}
			},
		)
	}
}

// _P5CheckFramed is _CheckFramed for the value of a row.
//
// Revisions:
//   - 2026-10-19 13:10: initial creation
func _P5CheckFramed(
	t *testing.T,
	aligned bool,
	row *_P5Row,
	alphabet *per.Alphabet,
) {
	t.Helper()

	value := _P5Value(
		t,
		row,
	)

	_CheckFramed(
		t,
		aligned,
		func(enc *per.Encoder) error {
			return _P5Encode(
				enc,
				row,
				alphabet,
				value,
			)
		},
		func(dec *per.Decoder) error {
			got, err := _P5Decode(
				dec,
				row,
				alphabet,
			)
			if err == nil && got != value {
				t.Errorf(
					"decode = %s, want %s",
					_P5Describe(got),
					_P5Describe(value),
				)
			}

			return err
		},
	)
}

// _P5Hex writes octets in lowercase hex, the form of testing.json (strings).
//
// Revisions:
//   - 2026-10-19 12:49: initial creation
func _P5Hex(octets []byte) string {
	return hex.EncodeToString(octets)
}
