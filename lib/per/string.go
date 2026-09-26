package per

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"unicode/utf8"
)

// Sentinel errors for the restricted character string types of X.691 clause 30.
var (
	ErrCharacterNotInAlphabet = errors.New("character is not in the type's alphabet")
	ErrUnknownStringKind      = errors.New("unknown string kind")
)

// StringKind names the ASN.1 restricted character string type a Go string
// carries, which its Go type cannot say on its own.
//
// It has to be said somewhere: X.691 clause 30.4 gives each known-multiplier
// type a different number of bits per character, so the same Go string encodes
// differently depending on which ASN.1 type it stands for.
type StringKind int

// _Variant is a PER variant, which decides how wide a character's bit-field is.
// It is an enumeration rather than a boolean so that no function below takes a
// bare true or false and decides what it means.
type _Variant int

// The two PER variants.
const (
	VARIANT_UNALIGNED _Variant = iota
	VARIANT_ALIGNED
)

// The restricted character string types this package encodes. STRING_UTF8 is the
// zero value and covers every type of clause 30.5, whose values PER carries as
// an octet string.
const (
	STRING_UTF8 StringKind = iota
	STRING_IA5
	STRING_VISIBLE
	STRING_PRINTABLE
	STRING_NUMERIC
	STRING_BMP
	STRING_UNIVERSAL
	STRING_KINDS
)

// The alphabets whose characters are not a contiguous range, in the canonical
// order of X.680 clause 43.3. Space sorts first in both, which is what makes it
// character zero after the renumbering of clause 30.4.4 b).
const (
	PRINTABLE_ORDER = " '()+,-./0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz"
	NUMERIC_ORDER = " 0123456789"
)

// STRING_NAMES maps the str= tag directive to the kind it names, and the
// alphabets of clause 30.4 are resolved once per variant.
//
// The number of bits per character depends on the variant, and whether the
// characters keep their own values or are renumbered depends on that in turn, so
// the two tables are built rather than written out.
var (
	STRING_NAMES = map[string]StringKind{
		"utf8":      STRING_UTF8,
		"ia5":       STRING_IA5,
		"visible":   STRING_VISIBLE,
		"printable": STRING_PRINTABLE,
		"numeric":   STRING_NUMERIC,
		"bmp":       STRING_BMP,
		"universal": STRING_UNIVERSAL,
	}
	ALPHABET_ALIGNED   = _Alphabets(VARIANT_ALIGNED)
	ALPHABET_UNALIGNED = _Alphabets(VARIANT_UNALIGNED)
)

// _Alphabet is one restricted character string type's effective alphabet, with
// the bit width and numbering clause 30.4 derives for one PER variant.
//
// order is the alphabet in canonical order, and is empty when the alphabet is
// the whole contiguous range lower..upper; index is that same order inverted, so
// a character's position is a lookup rather than a scan. compact records the
// outcome of clause 30.4.4: characters keep their own values unless the largest
// will not fit in the width, in which case they are renumbered from zero.
//
// kind is the type the alphabet belongs to, and ascii whether every character
// in it is a single byte of UTF-8 - which, for a Go string that is itself
// pure ASCII, means its bytes are its characters and no rune decoding is
// needed to walk them.
type _Alphabet struct {
	order   string
	index   *[ALPHABET_INDEX_SIZE]int16
	lower   rune
	upper   rune
	count   uint64
	bits    uint8
	kind    StringKind
	compact bool
	known   bool
	ascii   bool
}

// The NumericString packing: four bits per character, two to a byte, and how
// many characters the encoder hands to the kernel at a time. The chunk is a
// stack array in _WriteNumeric, so it is bounded rather than sized to the
// string.
const (
	NUMERIC_BITS   = 4
	NUMERIC_NIBBLE = 0x0F
	NUMERIC_PAIR   = 2
	NUMERIC_CHUNK  = 512
)

// ASCII_HIGH_BITS is the top bit of each byte in a word: a word with none of
// them set holds eight ASCII bytes. GROW_SLACK is the room reserved beyond a
// string's characters for its length determinant and any alignment padding.
const (
	ASCII_HIGH_BITS = 0x8080808080808080
	GROW_SLACK      = 8
)

// EncodeRestrictedString encodes a value of a restricted character string type,
// per X.691 clause 30.
//
// A known-multiplier type takes clause 30.4, which packs each character into the
// fewest bits its alphabet needs; every other type takes clause 30.5, which
// carries the value as an octet string.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation. EncodeString sent every Go string down
//     the octet string path, which is right for UTF8String and wrong for the
//     known-multiplier types: a UPER IA5String packs seven bits per character,
//     not eight, and NumericString packs four and renumbers them
func (e *Encoder) EncodeRestrictedString(value string, kind StringKind, size *Constraint) error {
	alphabet, err := e._Alphabet(kind)
	if err != nil {
		return err
	}

	if !alphabet.known {
		return e.EncodeOctetString(_StringBytes(value), size)
	}

	count := _CharacterCount(value)

	// Reserve the characters' bytes up front, so a long string grows the
	// buffer once rather than doubling its way up through it.
	e.codec.Grow(int(count)*int(alphabet.bits)/BITS_PER_BYTE + GROW_SLACK)

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeCharacters(value, count, alphabet, _Unbounded())
		}

		size = size._Root()
	}

	// Clause 30.4.6: a fixed length below 64K needs no determinant.
	if fixed, ok := size.Fixed(); ok && fixed < MAX_CONSTRAINED_LENGTH {
		return e._EncodeFixedCharacters(value, count, fixed, alphabet)
	}

	return e._EncodeCharacters(value, count, alphabet, size)
}

// DecodeRestrictedString decodes a value of a restricted character string type,
// per X.691 clause 30.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) DecodeRestrictedString(kind StringKind, size *Constraint) (string, error) {
	alphabet, err := d._Alphabet(kind)
	if err != nil {
		return "", err
	}

	if !alphabet.known {
		octets, err := d.DecodeOctetString(size)
		if err != nil {
			return "", err
		}

		return string(octets), nil
	}

	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return "", err
		}

		if outside {
			return d._DecodeCharacters(alphabet, _Unbounded())
		}

		size = size._Root()
	}

	if fixed, ok := size.Fixed(); ok && fixed < MAX_CONSTRAINED_LENGTH {
		if d._CharAligned(alphabet, fixed, CHAR_ALIGN_FIXED) {
			if err := d.codec.Advance(); err != nil {
				return "", err
			}
		}

		return d._ReadCharacters(fixed, alphabet)
	}

	return d._DecodeCharacters(alphabet, size)
}

// _Alphabet returns the effective alphabet of kind in this encoder's variant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _Alphabet(kind StringKind) (*_Alphabet, error) {
	if e.aligned {
		return _LookupAlphabet(ALPHABET_ALIGNED, kind)
	}

	return _LookupAlphabet(ALPHABET_UNALIGNED, kind)
}

// _Alphabet returns the effective alphabet of kind in this decoder's variant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _Alphabet(kind StringKind) (*_Alphabet, error) {
	if d.aligned {
		return _LookupAlphabet(ALPHABET_ALIGNED, kind)
	}

	return _LookupAlphabet(ALPHABET_UNALIGNED, kind)
}

// _CharAligned reports whether the bit-field of characters is octet-aligned.
//
// An unset upper bound means the field has no bound either, so it aligns.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _CharAligned(alphabet *_Alphabet, upper, floor uint64) bool {
	return e.aligned && _CharFieldAligns(alphabet, upper, floor)
}

// _CharAligned reports whether the bit-field of characters is octet-aligned.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _CharAligned(alphabet *_Alphabet, upper, floor uint64) bool {
	return d.aligned && _CharFieldAligns(alphabet, upper, floor)
}

// _EncodeFixedCharacters writes the characters of a type whose length cannot
// vary, per clause 30.4.6, which needs no length determinant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeRestrictedString
func (e *Encoder) _EncodeFixedCharacters(
	value string,
	count, fixed uint64,
	alphabet *_Alphabet,
) error {
	if count != fixed {
		return fmt.Errorf(
			"string of %d characters in a type fixed at %d: %w",
			count, fixed, ErrLengthMismatch,
		)
	}

	if e._CharAligned(alphabet, fixed, CHAR_ALIGN_FIXED) {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	if alphabet.ascii && uint64(len(value)) == count {
		return e._WriteASCII(_StringBytes(value), alphabet)
	}

	return e._WriteCharacters(value, alphabet)
}

// _EncodeCharacters writes a length determinant and the characters it counts,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _EncodeCharacters(
	value string,
	count uint64,
	alphabet *_Alphabet,
	size *Constraint,
) error {
	upper, bounded := size._SizeUpper()
	if !bounded {
		upper = MAX_CONSTRAINED_LENGTH
	}

	write := e._CharacterWriter(value, count, alphabet)
	offset := uint64(0)

	for {
		pending, err := e.EncodeLengthDeterminant(count-offset, size)
		if err != nil {
			return err
		}

		length := count - offset - pending

		if e._CharAligned(alphabet, upper, CHAR_ALIGN_BITS) {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}

		if err := write(offset, offset+length); err != nil {
			return err
		}

		offset = offset + length

		if pending != 0 {
			continue
		}

		return e._CloseFragments(count, offset, size)
	}
}

// _DecodeCharacters reads a length determinant and the characters it counts.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _DecodeCharacters(alphabet *_Alphabet, size *Constraint) (string, error) {
	upper, bounded := size._SizeUpper()
	if !bounded {
		upper = MAX_CONSTRAINED_LENGTH
	}

	var out strings.Builder

	for {
		length, more, err := d.DecodeLengthDeterminant(size)
		if err != nil {
			return "", err
		}

		if d._CharAligned(alphabet, upper, CHAR_ALIGN_BITS) {
			if err := d.codec.Advance(); err != nil {
				return "", err
			}
		}

		text, err := d._ReadCharacters(length, alphabet)
		if err != nil {
			return "", err
		}

		out.WriteString(text)

		if !more {
			return out.String(), nil
		}
	}
}

// _WriteCharacters writes every character of value as a bit-field.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _WriteCharacters(value string, alphabet *_Alphabet) error {
	for _, char := range value {
		if err := e._WriteRune(char, alphabet); err != nil {
			return err
		}
	}

	return nil
}

// _WriteRunes writes a run of characters as bit-fields.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _WriteRunes(runes []rune, alphabet *_Alphabet) error {
	for _, char := range runes {
		if err := e._WriteRune(char, alphabet); err != nil {
			return err
		}
	}

	return nil
}

// _CharacterWriter returns the function that writes a range of value's
// characters, chosen once for the whole string.
//
// A pure-ASCII string in an ASCII alphabet is walked as bytes - its bytes are
// its characters, so there is nothing to decode, and bytes are what the
// NumericString kernel takes. Anything else goes through runes, converted once
// here rather than per fragment, and an out-of-alphabet character is reported
// there exactly as it always was.
//
// Revisions:
//   - 2026-09-23 07:05: initial creation, split out of _EncodeCharacters
func (e *Encoder) _CharacterWriter(
	value string,
	count uint64,
	alphabet *_Alphabet,
) func(from, to uint64) error {
	if alphabet.ascii && uint64(len(value)) == count {
		text := _StringBytes(value)

		return func(from, to uint64) error {
			return e._WriteASCII(text[from:to], alphabet)
		}
	}

	runes := []rune(value)

	return func(from, to uint64) error {
		return e._WriteRunes(runes[from:to], alphabet)
	}
}

// _WriteASCII writes a run of single-byte characters as bit-fields. It is
// where NumericString leaves the per-character path.
//
// Revisions:
//   - 2026-09-23 05:45: initial creation
func (e *Encoder) _WriteASCII(text []byte, alphabet *_Alphabet) error {
	if alphabet.kind == STRING_NUMERIC {
		return e._WriteNumeric(text, alphabet)
	}

	for _, char := range text {
		if err := e._WriteRune(rune(char), alphabet); err != nil {
			return err
		}
	}

	return nil
}

// _WriteNumeric packs NumericString characters two to a byte with the kernels
// and writes the bytes, leaving an odd last character - and everything from
// the first character the kernels would not accept - to the per-character
// path.
//
// Two characters are one byte because clause 30.4 gives the eleven-character
// alphabet four bits in both variants, so a run of them is a byte string, and
// the bit buffer already places a byte string at any bit offset. The kernel
// therefore only looks up, validates and packs; it never touches the stream.
//
// The kernels stop at whole blocks - a pair, for the Go one - so a valid
// string leaves at most one character for the loop below, and an invalid one
// leaves everything from its pair on. Either way the loop reports what the
// kernels would not say, in the words it always used.
//
// Revisions:
//   - 2026-09-23 05:45: initial creation
//   - 2026-09-24 02:00: finishes with the Go kernel, so the per-character path
//     is left at most one valid character
func (e *Encoder) _WriteNumeric(text []byte, alphabet *_Alphabet) error {
	var (
		packed [NUMERIC_CHUNK / NUMERIC_PAIR]byte
	)

	for len(text) >= NUMERIC_PAIR {
		chunk := min(len(text), NUMERIC_CHUNK)

		done := _PackNumeric(packed[:], text[:chunk])
		done += _PackNumericGo(packed[done/NUMERIC_PAIR:], text[done:chunk])

		if done == 0 {
			break
		}

		if err := e.codec.WriteBytes(packed[:done/NUMERIC_PAIR]); err != nil {
			return err
		}

		text = text[done:]

		if done < chunk {
			break
		}
	}

	for _, char := range text {
		if err := e._WriteRune(rune(char), alphabet); err != nil {
			return err
		}
	}

	return nil
}

// _WriteRune writes one character as a bit-field of the alphabet's width.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _WriteRune(char rune, alphabet *_Alphabet) error {
	value, err := alphabet._Value(char)
	if err != nil {
		return err
	}

	return e.codec.Write(alphabet.bits, value)
}

// _ReadCharacters reads count characters, each a bit-field of the alphabet's
// width.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _ReadCharacters(count uint64, alphabet *_Alphabet) (string, error) {
	if alphabet.kind == STRING_NUMERIC {
		return d._ReadNumeric(count, alphabet)
	}

	var out strings.Builder

	for range count {
		value, err := d.codec.Read(alphabet.bits)
		if err != nil {
			return "", err
		}

		char, err := alphabet._Rune(value)
		if err != nil {
			return "", err
		}

		out.WriteRune(char)
	}

	return out.String(), nil
}

// _ReadNumeric reads count NumericString characters: the pairs as bytes,
// unpacked with the kernels, and an odd last character on its own.
//
// It is the mirror of _WriteNumeric. Reading the pairs as one byte string
// puts the misaligned case through the bit buffer's shift kernel, and the
// nibble kernels only have to split and look up. Whatever they do not consume
// - everything from a byte holding a nibble outside the alphabet - is unpacked
// by _UnpackScalar, which reports the error in the words the per-character
// path always used.
//
// Revisions:
//   - 2026-09-23 05:45: initial creation
//   - 2026-09-23 07:40: reads the pairs as a view rather than a copy, which is
//     free when the string is octet-aligned, and returns chars without copying
//     it into a string - three buffers per call became one
//   - 2026-09-24 02:00: finishes with the Go kernel, so _UnpackScalar is left only
//     the error
func (d *Decoder) _ReadNumeric(count uint64, alphabet *_Alphabet) (string, error) {
	var (
		pairs = int(count / NUMERIC_PAIR)
		chars = make([]byte, count)
	)

	if pairs > 0 {
		packed, err := d.codec.ReadView(pairs)
		if err != nil {
			return "", err
		}

		done := _UnpackNumeric(chars, packed)
		done += _UnpackNumericGo(chars[done*NUMERIC_PAIR:], packed[done:])

		err = _UnpackScalar(chars[done*NUMERIC_PAIR:], packed[done:], alphabet)
		if err != nil {
			return "", err
		}
	}

	if count%NUMERIC_PAIR != 0 {
		value, err := d.codec.Read(NUMERIC_BITS)
		if err != nil {
			return "", err
		}

		char, err := alphabet._Rune(value)
		if err != nil {
			return "", err
		}

		chars[count-1] = byte(char)
	}

	return _BytesString(chars), nil
}

// _UnpackScalar unpacks nibble pairs one byte at a time, high nibble first.
//
// Revisions:
//   - 2026-09-23 05:45: initial creation
func _UnpackScalar(chars, packed []byte, alphabet *_Alphabet) error {
	for idx, pair := range packed {
		high, err := alphabet._Rune(uint64(pair >> NUMERIC_BITS))
		if err != nil {
			return err
		}

		low, err := alphabet._Rune(uint64(pair & NUMERIC_NIBBLE))
		if err != nil {
			return err
		}

		chars[idx*NUMERIC_PAIR] = byte(high)
		chars[idx*NUMERIC_PAIR+1] = byte(low)
	}

	return nil
}

// _Value returns the number that stands for char in this alphabet, per clause
// 30.4.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (a *_Alphabet) _Value(char rune) (uint64, error) {
	if a.index != nil {
		index := a._Index(char)
		if index < 0 {
			return 0, fmt.Errorf("%q: %w", char, ErrCharacterNotInAlphabet)
		}

		if a.compact {
			return uint64(index), nil
		}

		return uint64(char), nil
	}

	if char < a.lower || char > a.upper {
		return 0, fmt.Errorf("%q: %w", char, ErrCharacterNotInAlphabet)
	}

	return uint64(char), nil
}

// _Index returns a character's position in the alphabet, or -1 if it has none.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation. The position used to come from
//     strings.IndexRune, which scans: 74 comparisons for a PrintableString
//     character in the worst case, on the path every character of every string
//     takes. Measured at half the time for a 15-character string
func (a *_Alphabet) _Index(char rune) int16 {
	if char < 0 || int(char) >= len(a.index) {
		return -1
	}

	return a.index[char]
}

// _Rune returns the character value stands for in this alphabet.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (a *_Alphabet) _Rune(value uint64) (rune, error) {
	if a.compact {
		if value >= uint64(len(a.order)) {
			return 0, fmt.Errorf("index %d: %w", value, ErrCharacterNotInAlphabet)
		}

		return rune(a.order[value]), nil
	}

	char := rune(value)
	if char < a.lower || char > a.upper {
		return 0, fmt.Errorf("value %d: %w", value, ErrCharacterNotInAlphabet)
	}

	if a.index != nil && a._Index(char) < 0 {
		return 0, fmt.Errorf("%q: %w", char, ErrCharacterNotInAlphabet)
	}

	return char, nil
}

// _CharacterCount returns the number of characters in value: its length when
// every byte is ASCII, and a rune count otherwise.
//
// The rune count was 40 % of the time to encode a 1 024-character
// NumericString. unicode/utf8 counts by decoding, one byte at a time, with no
// fast path for the common case; for a string whose bytes are all below 0x80
// the answer is len(value), and checking that eight bytes at a time is three
// to six times cheaper than counting. Every string this package encodes into a
// known-multiplier alphabet is such a string unless it is about to be rejected.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _CharacterCount(value string) uint64 {
	if _IsASCII(_StringBytes(value)) {
		return uint64(len(value))
	}

	return uint64(utf8.RuneCountInString(value))
}

// _IsASCII reports whether every byte of text is below 0x80, a word at a time.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _IsASCII(text []byte) bool {
	idx := 0

	for ; idx+UINT64_BYTES <= len(text); idx += UINT64_BYTES {
		if binary.LittleEndian.Uint64(text[idx:])&ASCII_HIGH_BITS != 0 {
			return false
		}
	}

	for ; idx < len(text); idx++ {
		if text[idx] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}

// _LookupAlphabet returns the alphabet of kind from one variant's table.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _LookupAlphabet(table []*_Alphabet, kind StringKind) (*_Alphabet, error) {
	if kind < 0 || int(kind) >= len(table) {
		return nil, fmt.Errorf("%d: %w", kind, ErrUnknownStringKind)
	}

	return table[kind], nil
}

// _CharFieldAligns reports whether a bit-field of upper characters reaches the
// width at which clauses 30.4.6 and 30.4.7 octet-align it.
//
// floor is where the two clauses differ and is the only thing that separates
// them: a length that can vary aligns at sixteen bits, a fixed one only above.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _CharFieldAligns(alphabet *_Alphabet, upper, floor uint64) bool {
	return upper*uint64(alphabet.bits) >= floor
}

// _Alphabets builds one variant's table of effective alphabets.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Alphabets(variant _Variant) []*_Alphabet {
	table := make([]*_Alphabet, STRING_KINDS)
	table[STRING_UTF8] = new(_Alphabet)
	table[STRING_IA5] = _MakeAlphabet("", 0, IA5_MAX, variant)
	table[STRING_VISIBLE] = _MakeAlphabet("", VISIBLE_MIN, VISIBLE_MAX, variant)
	table[STRING_PRINTABLE] = _MakeAlphabet(
		PRINTABLE_ORDER, PRINTABLE_MIN, PRINTABLE_MAX, variant,
	)
	table[STRING_NUMERIC] = _MakeAlphabet(NUMERIC_ORDER, NUMERIC_MIN, NUMERIC_MAX, variant)
	table[STRING_BMP] = _MakeAlphabet("", 0, BMP_MAX, variant)
	table[STRING_UNIVERSAL] = _MakeAlphabet("", 0, utf8.MaxRune, variant)

	// Set here rather than in _MakeAlphabet, which would need a fifth
	// parameter to learn what it already is by position in this table.
	for kind, alphabet := range table {
		alphabet.kind = StringKind(kind)
		alphabet.ascii = alphabet.known && alphabet.upper < utf8.RuneSelf
	}

	return table
}

// _MakeIndex inverts an alphabet, so that a character's position in it is a
// lookup rather than a scan.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation
func _MakeIndex(order string) *[ALPHABET_INDEX_SIZE]int16 {
	index := new([ALPHABET_INDEX_SIZE]int16)
	for i := range index {
		index[i] = -1
	}

	for i := range len(order) {
		index[order[i]] = int16(i)
	}

	return index
}

// _MakeAlphabet derives one alphabet's bit width and numbering from its
// character set, per clauses 30.4.2 and 30.4.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _MakeAlphabet(order string, lower, upper rune, variant _Variant) *_Alphabet {
	alphabet := &_Alphabet{
		order: order,
		lower: lower,
		upper: upper,
		count: uint64(upper-lower) + 1,
		known: true,
	}

	if order != "" {
		alphabet.count = uint64(len(order))
		alphabet.index = _MakeIndex(order)
	}

	// Clause 30.4.2: B is the smallest width that can number the alphabet, and
	// the ALIGNED variant rounds B up to a power of two.
	width := uint8(bits.Len64(alphabet.count - 1))
	if variant == VARIANT_ALIGNED {
		width = uint8(1) << bits.Len8(width-1)
	}

	alphabet.bits = width

	// Clause 30.4.4: the characters keep their own values if the largest fits in
	// the width, and are renumbered from zero if it does not.
	alphabet.compact = width < UINT64_BITS && uint64(upper) > uint64(1)<<width-1

	return alphabet
}
