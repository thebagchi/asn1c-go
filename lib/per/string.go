package per

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Sentinel errors for the restricted character string types of X.691 clause 30.
var (
	ErrCharacterNotInAlphabet = errors.New("character is not in the type's alphabet")
	ErrUnknownStringKind      = errors.New("unknown string kind")
	ErrInvalidUTF8            = errors.New("string is not well-formed UTF-8")
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
// zero value. It and the four kinds after STRING_UNIVERSAL are the types of
// clause 30.6, whose values PER carries as an octet string.
const (
	STRING_UTF8 StringKind = iota
	STRING_IA5
	STRING_VISIBLE
	STRING_PRINTABLE
	STRING_NUMERIC
	STRING_BMP
	STRING_UNIVERSAL
	STRING_GENERAL
	STRING_GRAPHIC
	STRING_TELETEX
	STRING_VIDEOTEX
	STRING_KINDS
)

// Aliases: T61String is TeletexString, and ISO646String is VisibleString (X.680
// clause 41, Table 8). They are names, not kinds.
const (
	STRING_T61    = STRING_TELETEX
	STRING_ISO646 = STRING_VISIBLE
)

// The alphabets whose characters are not a contiguous range, in the canonical
// order of X.680 clause 43.3. Space sorts first in both, which is what makes it
// character zero after the renumbering of clause 30.4.4 b).
const (
	PRINTABLE_ORDER = " '()+,-./0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz"
	NUMERIC_ORDER = " 0123456789"
)

// The alphabets of clause 30.4 are resolved once per variant.
//
// The number of bits per character depends on the variant, and whether the
// characters keep their own values or are renumbered depends on that in turn, so
// the two tables are built rather than written out.
var (
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
// ascii says whether every character
// in it is a single byte of UTF-8 - which, for a Go string that is itself
// pure ASCII, means its bytes are its characters and no rune decoding is
// needed to walk them. nibbles marks the NumericString parent alphabet, whose
// characters the kernels pack two to a byte.
//
// set is the sorted permitted set of a FROM alphabet that has a character above
// ASCII; it is nil for every other alphabet, whose order and index serve.
type _Alphabet struct {
	order   string
	index   *[ALPHABET_INDEX_SIZE]int16
	set     []rune
	lower   rune
	upper   rune
	count   uint64
	bits    uint8
	compact bool
	known   bool
	ascii   bool
	nibbles bool
}

// The NumericString packing: four bits per character, two to a byte, and how
// many characters the encoder hands to the kernel at a time. The chunk is a
// stack array in _WriteNumeric, so it is bounded rather than sized to the
// string.
const (
	UNIVERSAL_BITS = 32 // 30.5.3, the width of a UniversalString character
	NUMERIC_BITS   = 4
	NUMERIC_NIBBLE = 0x0F
	NUMERIC_PAIR   = 2
	NUMERIC_CHUNK  = 512
)

// ASCII_HIGH_BITS is the top bit of each byte in a word: a word with none of
// them set holds eight ASCII bytes. GROW_SLACK is the room reserved beyond a
// string's characters for its length determinant and any alignment padding.
//
// LANE_SIGN and LANE_LIMIT turn a range check of eight ASCII bytes into two additions:
// a lane x reaches its top bit with LANE_SIGN-lower added only when x >= lower, and with
// LANE_LIMIT-upper added only when x > upper. Neither sum carries out of its lane.
const (
	ASCII_HIGH_BITS = 0x8080808080808080
	GROW_SLACK      = 8
	LANE_SIGN       = 0x80
	LANE_LIMIT      = 0x7F
)

// The 7-bit packing of _WriteSeptets: the width of an IA5String, VisibleString or
// PrintableString character in UPER (X.691 30.5.2: B = 7), and how many characters it
// packs into one stack array before one write. 64 characters are 56 octets.
// _ReadSeptets reads SEPTET_WORD characters with one Read of SEPTET_WORD_BITS bits.
const (
	SEPTET_BITS         = 7
	SEPTET_CHUNK        = 64
	SEPTET_CHUNK_OCTETS = SEPTET_CHUNK * SEPTET_BITS / BITS_PER_BYTE
	SEPTET_WORD         = 8
	SEPTET_WORD_BITS    = SEPTET_WORD * SEPTET_BITS
	SEPTET_MASK         = 1<<SEPTET_BITS - 1
)

// The septet kernels: SEPTET_KERNEL_MIN is the shortest text that goes to them, and the
// AVX2 pack stores SEPTET_PACK_SLACK octets past its output, so a buffer for it has that
// room. The decoder reads SEPTET_SPREAD_GROUPS groups of SEPTET_GROUP_OCTETS octets into a
// stack array of SEPTET_SPREAD_OCTETS, which leaves room for the last store and the loads
// of the kernels, and spreads SEPTET_SPREAD_CHARS characters from it.
const (
	SEPTET_KERNEL_MIN    = 16
	SEPTET_PACK_SLACK    = 2
	SEPTET_GROUP_OCTETS  = 7
	SEPTET_SPREAD_GROUPS = 4
	SEPTET_SPREAD_CHARS  = SEPTET_SPREAD_GROUPS * SEPTET_WORD
	SEPTET_SPREAD_OCTETS = 32
)

// EncodeRestrictedString encodes a value of a restricted character string type,
// per X.691 clause 30.
//
// A known-multiplier type takes clause 30.5, which packs each character into the
// fewest bits its alphabet needs. Every other type takes clause 30.6, which carries
// the value as an octet string. size is PER-visible for the first group only: the
// second group ignores it (clauses 10.3.7 and 30.6).
//
// Revisions:
//   - 2026-09-22 06:43: initial creation. EncodeString sent every Go string down
//     the octet string path, which is right for UTF8String and wrong for the
//     known-multiplier types: a UPER IA5String packs seven bits per character,
//     not eight, and NumericString packs four and renumbers them
//   - 2026-10-19 10:38: split the root-length step into _EncodeRootCharacters to
//     stay under funlen; no behaviour change
//   - 2026-10-19 12:59: the clause 30.6 types ignore size and take the four new
//     kinds; the known-multiplier body moved to _EncodeKnown, which
//     EncodeAlphabetString shares (review P5-6)
func (e *Encoder) EncodeRestrictedString(
	value string,
	kind StringKind,
	size *Constraint,
) error {
	alphabet, err := e._Alphabet(kind)
	if err != nil {
		return err
	}

	if !alphabet.known {
		return e._EncodeOctetKind(
			value,
			kind,
		)
	}

	return e._EncodeKnown(
		value,
		alphabet,
		size,
	)
}

// _EncodeOctetKind encodes a value of a clause 30.6 type: an octet string with an
// unconstrained length, because no constraint on these types is PER-visible.
//
// UTF8String must hold well-formed UTF-8 (X.680 clause 41). The other types carry
// their octets unchanged.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-6, P5-9)
func (e *Encoder) _EncodeOctetKind(
	value string,
	kind StringKind,
) error {
	if kind == STRING_UTF8 && !utf8.ValidString(value) {
		return ErrInvalidUTF8
	}

	return e.EncodeOctetString(
		_StringBytes(value),
		Unconstrained(),
	)
}

// _EncodeKnown encodes a value of a known-multiplier type whose alphabet is
// resolved, per clauses 30.4 and 30.5. A FROM alphabet and a parent alphabet take
// this one path.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation, split out of EncodeRestrictedString
func (e *Encoder) _EncodeKnown(
	value string,
	alphabet *_Alphabet,
	size *Constraint,
) error {
	count, err := _CountCharacters(value)
	if err != nil {
		return err
	}

	// Reserve the characters' bytes up front, so a long string grows the
	// buffer once rather than doubling its way up through it.
	e.codec.Grow(int(count)*int(alphabet.bits)/BITS_PER_BYTE + GROW_SLACK)

	if size.HasExtension() {
		outside := !size._CoversLength(count)
		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			return e._EncodeCharacters(
				value,
				count,
				alphabet,
				_Unbounded(),
			)
		}

		size = size._Root()
	}

	return e._EncodeRootCharacters(
		value,
		count,
		alphabet,
		size,
	)
}

// _EncodeRootCharacters encodes the characters of a known-multiplier string
// whose length lies in the root of size.
//
// A fixed length below 64K needs no determinant (clause 30.4.6).
//
// Revisions:
//   - 2026-10-19 10:38: initial creation
//   - 2026-10-19 11:14: refuses a length outside the size constraint (review P3-1)
func (e *Encoder) _EncodeRootCharacters(
	value string,
	count uint64,
	alphabet *_Alphabet,
	size *Constraint,
) error {
	if fixed, ok := size.Fixed(); ok && fixed < MAX_CONSTRAINED_LENGTH {
		return e._EncodeFixedCharacters(
			value,
			count,
			fixed,
			alphabet,
		)
	}

	if err := size._CheckLength(count); err != nil {
		return err
	}

	return e._EncodeCharacters(
		value,
		count,
		alphabet,
		size,
	)
}

// DecodeRestrictedString decodes a value of a restricted character string type,
// per X.691 clause 30.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 10:38: split the root-length step into _DecodeRootCharacters to
//     stay under funlen; no behaviour change
//   - 2026-10-19 12:59: the clause 30.6 types ignore size and take the four new
//     kinds; the known-multiplier body moved to _DecodeKnown, which
//     DecodeAlphabetString shares (review P5-6)
func (d *Decoder) DecodeRestrictedString(
	kind StringKind,
	size *Constraint,
) (string, error) {
	alphabet, err := d._Alphabet(kind)
	if err != nil {
		return "", err
	}

	if !alphabet.known {
		return d._DecodeOctetKind(kind)
	}

	return d._DecodeKnown(
		alphabet,
		size,
	)
}

// _DecodeOctetKind decodes a value of a clause 30.6 type: an octet string with an
// unconstrained length. A UTF8String that is not well-formed UTF-8 is refused.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-6, P5-9)
//   - 2026-10-19 13:16: hands the octets over as the string, with no second copy (review P5-10)
func (d *Decoder) _DecodeOctetKind(kind StringKind) (string, error) {
	octets, err := d.DecodeOctetString(Unconstrained())
	if err != nil {
		return "", err
	}

	if kind == STRING_UTF8 && !utf8.Valid(octets) {
		return "", ErrInvalidUTF8
	}

	// DecodeOctetString returns a fresh buffer that nothing else keeps.
	return _BytesString(octets), nil
}

// _DecodeKnown decodes a value of a known-multiplier type whose alphabet is
// resolved, per clauses 30.4 and 30.5.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation, split out of DecodeRestrictedString
func (d *Decoder) _DecodeKnown(
	alphabet *_Alphabet,
	size *Constraint,
) (string, error) {
	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return "", err
		}

		if outside {
			return d._DecodeCharacters(
				alphabet,
				_Unbounded(),
			)
		}

		size = size._Root()
	}

	return d._DecodeRootCharacters(
		alphabet,
		size,
	)
}

// _DecodeRootCharacters decodes the characters of a known-multiplier string
// whose length lies in the root of size.
//
// Revisions:
//   - 2026-10-19 10:38: initial creation
func (d *Decoder) _DecodeRootCharacters(
	alphabet *_Alphabet,
	size *Constraint,
) (string, error) {
	if fixed, ok := size.Fixed(); ok && fixed < MAX_CONSTRAINED_LENGTH {
		if d._CharAligned(
			alphabet,
			fixed,
			CHAR_ALIGN_FIXED,
		) {
			if err := d.codec.Advance(); err != nil {
				return "", err
			}
		}

		return d._ReadCharacters(
			fixed,
			alphabet,
		)
	}

	return d._DecodeCharacters(
		alphabet,
		size,
	)
}

// _Alphabet returns the effective alphabet of kind in this encoder's variant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _Alphabet(kind StringKind) (*_Alphabet, error) {
	if e.aligned {
		return _LookupAlphabet(
			ALPHABET_ALIGNED,
			kind,
		)
	}

	return _LookupAlphabet(
		ALPHABET_UNALIGNED,
		kind,
	)
}

// _Alphabet returns the effective alphabet of kind in this decoder's variant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _Alphabet(kind StringKind) (*_Alphabet, error) {
	if d.aligned {
		return _LookupAlphabet(
			ALPHABET_ALIGNED,
			kind,
		)
	}

	return _LookupAlphabet(
		ALPHABET_UNALIGNED,
		kind,
	)
}

// _CharAligned reports whether the bit-field of characters is octet-aligned.
//
// An unset upper bound means the field has no bound either, so it aligns.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _CharAligned(
	alphabet *_Alphabet,
	upper,
	floor uint64,
) bool {
	return e.aligned && _CharFieldAligns(
		alphabet,
		upper,
		floor,
	)
}

// _CharAligned reports whether the bit-field of characters is octet-aligned.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (d *Decoder) _CharAligned(
	alphabet *_Alphabet,
	upper,
	floor uint64,
) bool {
	return d.aligned && _CharFieldAligns(
		alphabet,
		upper,
		floor,
	)
}

// _EncodeFixedCharacters writes the characters of a type whose length cannot
// vary, per clause 30.4.6, which needs no length determinant.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of EncodeRestrictedString
func (e *Encoder) _EncodeFixedCharacters(
	value string,
	count,
	fixed uint64,
	alphabet *_Alphabet,
) error {
	if count != fixed {
		return fmt.Errorf(
			"string of %d characters in a type fixed at %d: %w",
			count,
			fixed,
			ErrLengthMismatch,
		)
	}

	if e._CharAligned(
		alphabet,
		fixed,
		CHAR_ALIGN_FIXED,
	) {
		if err := e.codec.Align(); err != nil {
			return err
		}
	}

	if alphabet.ascii && uint64(len(value)) == count {
		return e._WriteASCII(
			_StringBytes(value),
			alphabet,
		)
	}

	return e._WriteCharacters(
		value,
		alphabet,
	)
}

// _EncodeCharacters writes a length determinant and the characters it counts,
// fragmenting when clause 11.9.3.8 calls for it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 10:38: split the fragment opening into _OpenFragment to stay under
//     funlen; no behaviour change
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

	write := e._CharacterWriter(
		value,
		count,
		alphabet,
	)

	for offset := uint64(0); ; {
		pending, err := e._OpenFragment(
			count-offset,
			size,
			alphabet,
			upper,
		)
		if err != nil {
			return err
		}

		length := count - offset - pending

		if err := write(
			offset,
			offset+length,
		); err != nil {
			return err
		}

		offset = offset + length

		if pending != 0 {
			continue
		}

		return e._CloseFragments(
			count,
			offset,
			size,
		)
	}
}

// _OpenFragment writes the length determinant of one fragment of remaining
// characters, then aligns when the alphabet needs it. It returns the number of
// characters the determinant leaves for later fragments.
//
// Revisions:
//   - 2026-10-19 10:38: initial creation
func (e *Encoder) _OpenFragment(
	remaining uint64,
	size *Constraint,
	alphabet *_Alphabet,
	upper uint64,
) (uint64, error) {
	pending, err := e.EncodeLengthDeterminant(
		remaining,
		size,
	)
	if err != nil {
		return 0, err
	}

	if e._CharAligned(
		alphabet,
		upper,
		CHAR_ALIGN_BITS,
	) {
		if err := e.codec.Align(); err != nil {
			return 0, err
		}
	}

	return pending, nil
}

// _DecodeCharacters reads a length determinant and the characters it counts.
//
// A value of one fragment allocates the result string only. A fragmented value
// (clause 11.9.3.8) knows its count one fragment at a time, so it allocates more:
// one string for each fragment and the joined result.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 11:14: refuses a total length outside the size constraint (review P3-1)
//   - 2026-10-19 13:16: returns the string of a single fragment as it is (review P5-10)
func (d *Decoder) _DecodeCharacters(
	alphabet *_Alphabet,
	size *Constraint,
) (string, error) {
	upper, bounded := size._SizeUpper()
	if !bounded {
		upper = MAX_CONSTRAINED_LENGTH
	}

	var (
		out   strings.Builder
		total uint64
	)

	for {
		length, more, err := d.DecodeLengthDeterminant(size)
		if err != nil {
			return "", err
		}

		total = total + length
		if err := size._CheckUpper(total); err != nil {
			return "", err
		}

		text, err := d._ReadFragment(
			length,
			alphabet,
			upper,
		)
		if err != nil {
			return "", err
		}

		// One fragment is the usual case: its string is the result, with no copy.
		if !more && total == length {
			return text, size._CheckLength(total)
		}

		out.WriteString(text)

		if !more {
			return out.String(), size._CheckLength(total)
		}
	}
}

// _ReadFragment aligns when clause 30.5.7 asks for it, then reads the length
// characters of one fragment.
//
// Revisions:
//   - 2026-10-19 13:19: initial creation, split out of _DecodeCharacters to stay under funlen
//     (review P5-10)
func (d *Decoder) _ReadFragment(
	length uint64,
	alphabet *_Alphabet,
	upper uint64,
) (string, error) {
	if d._CharAligned(
		alphabet,
		upper,
		CHAR_ALIGN_BITS,
	) {
		if err := d.codec.Advance(); err != nil {
			return "", err
		}
	}

	return d._ReadCharacters(
		length,
		alphabet,
	)
}

// _WriteCharacters writes every character of value as a bit-field.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _WriteCharacters(
	value string,
	alphabet *_Alphabet,
) error {
	for _, char := range value {
		if err := e._WriteRune(
			char,
			alphabet,
		); err != nil {
			return err
		}
	}

	return nil
}

// _WriteRunes writes a run of characters as bit-fields.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (e *Encoder) _WriteRunes(
	runes []rune,
	alphabet *_Alphabet,
) error {
	for _, char := range runes {
		if err := e._WriteRune(
			char,
			alphabet,
		); err != nil {
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
) func(
	from,
	to uint64,
) error {
	if alphabet.ascii && uint64(len(value)) == count {
		text := _StringBytes(value)

		return func(
			from,
			to uint64,
		) error {
			return e._WriteASCII(
				text[from:to],
				alphabet,
			)
		}
	}

	runes := []rune(value)

	return func(
		from,
		to uint64,
	) error {
		return e._WriteRunes(
			runes[from:to],
			alphabet,
		)
	}
}

// _WriteASCII writes a run of single-byte characters as bit-fields. It is
// where NumericString leaves the per-character path, and where an 8-bit
// alphabet that keeps its own values writes its octets in one call.
//
// Revisions:
//   - 2026-09-23 05:45: initial creation
//   - 2026-10-20 01:39: writes the octets with one WriteBytes when the width is 8
//     bits and the alphabet is not compact (review P13-5)
//   - 2026-10-21 02:45: packs 7-bit characters with _WriteSeptets when the alphabet is not
//     compact (review P19-1)
func (e *Encoder) _WriteASCII(
	text []byte,
	alphabet *_Alphabet,
) error {
	if alphabet.nibbles {
		return e._WriteNumeric(
			text,
			alphabet,
		)
	}

	octets := alphabet.bits == BITS_PER_BYTE && !alphabet.compact
	if octets {
		return e._WriteOctets(
			text,
			alphabet,
		)
	}

	septets := alphabet.bits == SEPTET_BITS && !alphabet.compact
	if septets {
		return e._WriteSeptets(
			text,
			alphabet,
		)
	}

	for _, char := range text {
		if err := e._WriteRune(
			rune(char),
			alphabet,
		); err != nil {
			return err
		}
	}

	return nil
}

// _WriteOctets writes characters of an 8-bit alphabet that keeps its own values.
// Clause 30.5.4 a) then makes the value of each character its octet, so the
// text is its own bit-field. Each byte is checked first, so a byte outside
// the alphabet returns the same error as on the per-character path and
// nothing is written.
//
// Revisions:
//   - 2026-10-20 01:39: initial creation (review P13-5)
//   - 2026-10-21 13:16: checks the bytes with _CheckBytes, in place of one _Value call per
//     character (review P27)
func (e *Encoder) _WriteOctets(
	text []byte,
	alphabet *_Alphabet,
) error {
	if err := alphabet._CheckBytes(text); err != nil {
		return err
	}

	return e.codec.WriteBytes(text)
}

// _WriteSeptets writes characters of a 7-bit alphabet that keeps its own values.
// Clause 30.5.4 a) then makes the value of each character its byte, so the
// characters pack into a bit-field of 7 bits each. Each byte is checked first, so a
// byte outside the alphabet returns the same error as on the per-character path and
// nothing is written. The packing goes through a stack array of SEPTET_CHUNK
// characters, and WriteBits writes each chunk with one call, at any bit offset.
//
// Revisions:
//   - 2026-10-21 02:45: initial creation (review P19-1)
//   - 2026-10-21 13:16: checks the bytes with _CheckBytes, in place of one _Value call per
//     character (review P27)
//   - 2026-10-21 22:05: the stack array has the SEPTET_PACK_SLACK octets the AVX2 pack stores past
//     its output (review P32)
func (e *Encoder) _WriteSeptets(
	text []byte,
	alphabet *_Alphabet,
) error {
	if err := alphabet._CheckBytes(text); err != nil {
		return err
	}

	var (
		packed [SEPTET_CHUNK_OCTETS + SEPTET_PACK_SLACK]byte
	)

	for len(text) > 0 {
		var (
			chunk = min(
				len(text),
				SEPTET_CHUNK,
			)

			filled = _PackSeptets(
				packed[:],
				text[:chunk],
			)
		)
		if err := e.WriteBits(
			packed[:filled],
			uint64(chunk)*SEPTET_BITS,
		); err != nil {
			return err
		}

		text = text[chunk:]
	}

	return nil
}

// _PackSeptets packs the low 7 bits of each byte of text into dst, leading bit first,
// and returns how many octets it filled. A text of SEPTET_KERNEL_MIN characters or more
// goes to the kernels first; each block of sixteen characters is fourteen whole octets, so
// the shift takes the rest from an octet boundary.
//
// Revisions:
//   - 2026-10-21 02:45: initial creation (review P19-1)
//   - 2026-10-21 22:05: the SSE2 and AVX2 kernels take whole blocks, and the shift the rest
//     (review P32)
//   - 2026-10-21 22:41: a short text goes to the shift at once, with no slices to check: the
//     8-character encode measured 3 percent slower in both orders (review P32)
func _PackSeptets(
	dst []byte,
	text []byte,
) int {
	if len(text) < SEPTET_KERNEL_MIN {
		return _PackSeptetsShift(
			dst,
			text,
		)
	}

	var (
		done = _PackSeptetKernels(
			dst,
			text,
		)
		out = done * SEPTET_BITS / BITS_PER_BYTE
	)

	return out + _PackSeptetsShift(
		dst[out:],
		text[done:],
	)
}

// _PackSeptetsShift packs the low 7 bits of each byte of text into dst, leading bit first,
// and returns how many octets it filled. The last octet holds the rest bits at its top. The
// work is shifts into one word, an octet out each time eight bits are held.
//
// Revisions:
//   - 2026-10-21 02:45: initial creation (review P19-1), as _PackSeptets
//   - 2026-10-21 22:05: _PackSeptetsShift, the tail of _PackSeptets and the oracle of the kernels
//     (review P32)
func _PackSeptetsShift(
	dst []byte,
	text []byte,
) int {
	var (
		word uint64
		held uint64
		out  int
	)

	for _, char := range text {
		word = word<<SEPTET_BITS | uint64(char)
		held += SEPTET_BITS

		if held >= BITS_PER_BYTE {
			held -= BITS_PER_BYTE
			dst[out] = byte(word >> held)
			out++
		}
	}

	if held > 0 {
		dst[out] = byte(word << (BITS_PER_BYTE - held))
		out++
	}

	return out
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
func (e *Encoder) _WriteNumeric(
	text []byte,
	alphabet *_Alphabet,
) error {
	var (
		packed [NUMERIC_CHUNK / NUMERIC_PAIR]byte
	)

	for len(text) >= NUMERIC_PAIR {
		var (
			chunk = min(
				len(text),
				NUMERIC_CHUNK,
			)

			done = _PackNumeric(
				packed[:],
				text[:chunk],
			)
		)

		done += _PackNumericGo(
			packed[done/NUMERIC_PAIR:],
			text[done:chunk],
		)

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
		if err := e._WriteRune(
			rune(char),
			alphabet,
		); err != nil {
			return err
		}
	}

	return nil
}

// _WriteRune writes one character as a bit-field of the alphabet's width.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 12:59: writes no bits for a one-character FROM alphabet in UPER (review P5-8)
func (e *Encoder) _WriteRune(
	char rune,
	alphabet *_Alphabet,
) error {
	value, err := alphabet._Value(char)
	if err != nil {
		return err
	}

	// A one-character alphabet has no bits in the UNALIGNED variant (clause
	// 30.5.2: B = 0), so the character is only checked.
	if alphabet.bits == 0 {
		return nil
	}

	return e.codec.Write(
		alphabet.bits,
		value,
	)
}

// _ReadCharacters reads count characters, each a bit-field of the alphabet's
// width.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 12:59: reads the number through _ReadCharacter (review P5-8)
//   - 2026-10-19 13:16: builds the result in one buffer of the right size and hands it over
//     as the string, where a strings.Builder grew and copied (review P5-10)
//   - 2026-10-21 17:25: an ASCII alphabet that keeps its own values reads its 8-bit or
//     7-bit characters in one pass, with the gate of the writers (review P29-1)
func (d *Decoder) _ReadCharacters(
	count uint64,
	alphabet *_Alphabet,
) (string, error) {
	if alphabet.nibbles {
		return d._ReadNumeric(
			count,
			alphabet,
		)
	}

	own := alphabet.ascii && !alphabet.compact
	if own && alphabet.bits == BITS_PER_BYTE {
		return d._ReadOctets(
			count,
			alphabet,
		)
	}

	if own && alphabet.bits == SEPTET_BITS {
		return d._ReadSeptets(
			count,
			alphabet,
		)
	}

	// The count is known, so the buffer is sized once: the longest UTF-8 form of
	// the alphabet's largest character, for each character. The bytes become the
	// string without a copy; nothing else keeps them.
	out := make(
		[]byte,
		0,
		count*uint64(utf8.RuneLen(alphabet.upper)),
	)

	for range count {
		value, err := d._ReadCharacter(alphabet)
		if err != nil {
			return "", err
		}

		char, err := alphabet._Rune(value)
		if err != nil {
			return "", err
		}

		out = utf8.AppendRune(
			out,
			char,
		)
	}

	return _BytesString(out), nil
}

// _ReadCharacter reads the bit-field of one character. A one-character FROM
// alphabet has no bits in the UNALIGNED variant (clause 30.5.2: B = 0), and its
// character is number 0.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-8)
func (d *Decoder) _ReadCharacter(alphabet *_Alphabet) (uint64, error) {
	if alphabet.bits == 0 {
		return 0, nil
	}

	return d.codec.Read(alphabet.bits)
}

// _ReadOctets reads count characters of an 8-bit alphabet that keeps its own values. Clause
// 30.5.4 a) makes each octet the character, so the text is one byte string: one read, one
// check, and the bytes become the string with no copy. A bad byte returns the error of
// _Rune, as on the per-character path.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func (d *Decoder) _ReadOctets(
	count uint64,
	alphabet *_Alphabet,
) (string, error) {
	text, err := d.codec.ReadBytes(int(count))
	if err != nil {
		return "", err
	}

	if err := alphabet._CheckValues(text); err != nil {
		return "", err
	}

	// ReadBytes returns a fresh buffer that nothing else keeps.
	return _BytesString(text), nil
}

// _ReadSeptets reads count characters of a 7-bit alphabet that keeps its own values: the
// reverse of _PackSeptets. Where the kernels exist, whole chunks of SEPTET_SPREAD_CHARS go
// through _ReadSeptetChunks. Each Read after them takes SEPTET_WORD characters at once, and
// a last Read takes the rest, so the reads are an eighth of the characters at any bit
// offset. The buffer is the result, as in _ReadCharacters.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
//   - 2026-10-21 22:05: whole chunks go through the spread kernels first (review P32)
//   - 2026-10-21 22:41: calls _ReadSeptetChunks only for a whole chunk: the call and its
//     stack array made the 8-character decode 8 to 10 percent slower (review P32)
func (d *Decoder) _ReadSeptets(
	count uint64,
	alphabet *_Alphabet,
) (string, error) {
	var (
		text = make(
			[]byte,
			count,
		)
		at uint64
	)

	if SEPTET_KERNELS && count >= SEPTET_SPREAD_CHARS {
		read, err := d._ReadSeptetChunks(text)
		if err != nil {
			return "", err
		}

		at = read
	}

	for ; at < count; at += SEPTET_WORD {
		var (
			chars = min(
				count-at,
				SEPTET_WORD,
			)

			word, err = d.codec.Read(uint8(chars * SEPTET_BITS))
		)
		if err != nil {
			return "", err
		}

		_SpreadSeptets(
			text[at:at+chars],
			word,
		)
	}

	if err := alphabet._CheckValues(text); err != nil {
		return "", err
	}

	return _BytesString(text), nil
}

// _ReadSeptetChunks reads whole chunks of SEPTET_SPREAD_CHARS characters into text and
// returns how many it read. Four Reads of SEPTET_WORD_BITS fill a stack array with the
// packed octets, at any bit offset, and the kernels spread them; a group the kernels leave
// is spread here from the same array, so the result does not hang on their reach.
//
// Revisions:
//   - 2026-10-21 22:05: initial creation (review P32)
func (d *Decoder) _ReadSeptetChunks(text []byte) (uint64, error) {
	var (
		packed [SEPTET_SPREAD_OCTETS]byte
		at     int
	)

	for ; at+SEPTET_SPREAD_CHARS <= len(text); at += SEPTET_SPREAD_CHARS {
		for group := range SEPTET_SPREAD_GROUPS {
			word, err := d.codec.Read(SEPTET_WORD_BITS)
			if err != nil {
				return 0, err
			}

			binary.BigEndian.PutUint64(
				packed[group*SEPTET_GROUP_OCTETS:],
				word<<BITS_PER_BYTE,
			)
		}

		var (
			chunk = text[at : at+SEPTET_SPREAD_CHARS]
			done  = _SpreadSeptetKernels(
				chunk,
				packed[:],
			)
		)

		for group := done / SEPTET_WORD; group < SEPTET_SPREAD_GROUPS; group++ {
			_SpreadSeptets(
				chunk[group*SEPTET_WORD:(group+1)*SEPTET_WORD],
				binary.BigEndian.Uint64(
					packed[group*SEPTET_GROUP_OCTETS:],
				)>>BITS_PER_BYTE,
			)
		}
	}

	return uint64(at), nil
}

// _SpreadSeptets puts the 7-bit fields of word into dst, one to a byte, the leading field
// first. word holds len(dst) fields in its low bits.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func _SpreadSeptets(
	dst []byte,
	word uint64,
) {
	shift := uint(len(dst)) * SEPTET_BITS

	for idx := range dst {
		shift -= SEPTET_BITS
		dst[idx] = byte(word>>shift) & SEPTET_MASK
	}
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
//   - 2026-10-19 10:38: split the pair unpacking into _ReadNumericPairs to stay under
//     funlen; no behaviour change
func (d *Decoder) _ReadNumeric(
	count uint64,
	alphabet *_Alphabet,
) (string, error) {
	var (
		pairs = int(count / NUMERIC_PAIR)
		chars = make(
			[]byte,
			count,
		)
	)

	if pairs > 0 {
		err := d._ReadNumericPairs(
			chars,
			pairs,
			alphabet,
		)
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

// _ReadNumericPairs reads pairs nibble pairs and unpacks them into chars.
//
// Revisions:
//   - 2026-10-19 10:38: initial creation
func (d *Decoder) _ReadNumericPairs(
	chars []byte,
	pairs int,
	alphabet *_Alphabet,
) error {
	packed, err := d.codec.ReadView(pairs)
	if err != nil {
		return err
	}

	done := _UnpackNumeric(
		chars,
		packed,
	)
	done += _UnpackNumericGo(
		chars[done*NUMERIC_PAIR:],
		packed[done:],
	)

	return _UnpackScalar(
		chars[done*NUMERIC_PAIR:],
		packed[done:],
		alphabet,
	)
}

// _UnpackScalar unpacks nibble pairs one byte at a time, high nibble first.
//
// Revisions:
//   - 2026-09-23 05:45: initial creation
func _UnpackScalar(
	chars,
	packed []byte,
	alphabet *_Alphabet,
) error {
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
//   - 2026-10-19 12:59: a FROM alphabet with a character above ASCII takes its
//     position from a sorted set (review P5-4)
func (a *_Alphabet) _Value(char rune) (uint64, error) {
	if a.set != nil {
		return a._SetValue(char)
	}

	if a.index != nil {
		index := a._Index(char)
		if index < 0 {
			return 0, fmt.Errorf(
				"%q: %w",
				char,
				ErrCharacterNotInAlphabet,
			)
		}

		if a.compact {
			return uint64(index), nil
		}

		return uint64(char), nil
	}

	if char < a.lower || char > a.upper {
		return 0, fmt.Errorf(
			"%q: %w",
			char,
			ErrCharacterNotInAlphabet,
		)
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

// _CheckBytes returns the error _Value gives for the first byte of text that is outside
// the alphabet, or nil. text is single-byte characters of an alphabet below 0x80. One
// call checks the whole text, so a valid string pays no call per character.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation (review P27)
//   - 2026-10-21 17:25: finds the byte with _OutsideTable or _OutsideRange, which the
//     decoder shares (review P29-1)
func (a *_Alphabet) _CheckBytes(text []byte) error {
	var (
		at int
	)

	if a.index != nil {
		at = a._OutsideTable(text)
	} else {
		at = a._OutsideRange(text)
	}

	if at == len(text) {
		return nil
	}

	_, err := a._Value(rune(text[at]))

	return err
}

// _CheckValues returns the error _Rune gives for the first byte of text that is outside
// the alphabet, or nil. It is _CheckBytes for decoded text, whose bytes are values: the
// error names the value, as the per-character path did. Each check picks the table or
// the range itself: a shared function for the choice is one call more per string, and
// that call measured 1 to 4 percent on an 8-character encode.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-1)
func (a *_Alphabet) _CheckValues(text []byte) error {
	var (
		at int
	)

	if a.index != nil {
		at = a._OutsideTable(text)
	} else {
		at = a._OutsideRange(text)
	}

	if at == len(text) {
		return nil
	}

	_, err := a._Rune(uint64(text[at]))

	return err
}

// _OutsideTable checks each byte of text against the index of the alphabet. A table has
// no word form, so each byte costs one load.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation (review P27), as _CheckTable
//   - 2026-10-21 17:25: returns the place of the byte, or len(text); the callers make the
//     error (review P29-1)
func (a *_Alphabet) _OutsideTable(text []byte) int {
	index := a.index

	for at, char := range text {
		if int(char) >= len(index) || index[char] < 0 {
			return at
		}
	}

	return len(text)
}

// _OutsideRange checks text against the range lower to upper. A text of RANGE_KERNEL_MIN
// bytes or more goes to the assembly kernels first. The rest goes eight bytes to a word: a
// lane past ASCII sets its own top bit, and the two additions of LANE_SIGN and LANE_LIMIT
// flag a lane outside the range (see their comment). A word with a flag stops the loop,
// and the bytes from that word on take the plain compare, which finds the byte.
//
// Revisions:
//   - 2026-10-21 13:16: initial creation (review P27), as _CheckRange
//   - 2026-10-21 16:08: a text of RANGE_KERNEL_MIN bytes or more goes to the SSE2 and
//     AVX2 kernels first (review P28)
//   - 2026-10-21 17:25: returns the place of the byte; the callers make the error
//     (review P29-1)
func (a *_Alphabet) _OutsideRange(text []byte) int {
	var (
		below = LOW_BIT_LANES * uint64(LANE_SIGN-a.lower)
		above = LOW_BIT_LANES * uint64(LANE_LIMIT-a.upper)
		at    int
	)

	if len(text) >= RANGE_KERNEL_MIN {
		at = _CheckRangeKernels(
			text,
			byte(a.lower),
			byte(a.upper),
		)
	}

	for ; at+UINT64_BYTES <= len(text); at += UINT64_BYTES {
		var (
			word = binary.LittleEndian.Uint64(text[at:])

			outside = (word | ^(word + below) | (word + above)) & ASCII_HIGH_BITS
		)
		if outside != 0 {
			break
		}
	}

	for ; at < len(text); at++ {
		char := rune(text[at])
		if char < a.lower || char > a.upper {
			return at
		}
	}

	return len(text)
}

// _Rune returns the character value stands for in this alphabet.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 12:59: refuses a surrogate, which is no character of ISO/IEC 10646;
//     a FROM alphabet with a character above ASCII takes its character from a
//     sorted set (review P5-9)
func (a *_Alphabet) _Rune(value uint64) (rune, error) {
	if a.set != nil {
		return a._SetRune(value)
	}

	if a.compact {
		if value >= uint64(len(a.order)) {
			return 0, fmt.Errorf(
				"index %d: %w",
				value,
				ErrCharacterNotInAlphabet,
			)
		}

		return rune(a.order[value]), nil
	}

	char := rune(value)
	if char < a.lower || char > a.upper {
		return 0, fmt.Errorf(
			"value %d: %w",
			value,
			ErrCharacterNotInAlphabet,
		)
	}

	if a.index != nil && a._Index(char) < 0 || _IsSurrogate(char) {
		return 0, fmt.Errorf(
			"%q: %w",
			char,
			ErrCharacterNotInAlphabet,
		)
	}

	return char, nil
}

// _CountCharacters returns the number of characters in value: its length when
// every byte is ASCII, and a rune count otherwise. A string that is not
// well-formed UTF-8 is refused, because a range over it would turn a bad byte into
// U+FFFD, which is a character of BMPString and UniversalString (review P5-9).
//
// The rune count was 40 % of the time to encode a 1 024-character
// NumericString. unicode/utf8 counts by decoding, one byte at a time, with no
// fast path for the common case; for a string whose bytes are all below 0x80
// the answer is len(value), and checking that eight bytes at a time is three
// to six times cheaper than counting. Every string this package encodes into a
// known-multiplier alphabet is such a string unless it is about to be rejected.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation, as _CharacterCount
//   - 2026-10-19 12:59: refuses invalid UTF-8 and returns an error (review P5-9)
func _CountCharacters(value string) (uint64, error) {
	if _IsASCII(_StringBytes(value)) {
		return uint64(len(value)), nil
	}

	if !utf8.ValidString(value) {
		return 0, ErrInvalidUTF8
	}

	return uint64(utf8.RuneCountInString(value)), nil
}

// _IsSurrogate reports whether char lies in the surrogate block, which holds no
// character of ISO/IEC 10646.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-9)
func _IsSurrogate(char rune) bool {
	return char >= SURROGATE_MIN && char <= SURROGATE_MAX
}

// _SetValue returns the number that stands for char in an alphabet that holds a
// sorted set of characters, per clause 30.5.4.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-4)
func (a *_Alphabet) _SetValue(char rune) (uint64, error) {
	index, found := slices.BinarySearch(
		a.set,
		char,
	)
	if !found {
		return 0, fmt.Errorf(
			"%q: %w",
			char,
			ErrCharacterNotInAlphabet,
		)
	}

	if a.compact {
		return uint64(index), nil
	}

	return uint64(char), nil
}

// _SetRune returns the character that value stands for in an alphabet that holds a
// sorted set of characters.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-4)
func (a *_Alphabet) _SetRune(value uint64) (rune, error) {
	if a.compact {
		if value >= uint64(len(a.set)) {
			return 0, fmt.Errorf(
				"index %d: %w",
				value,
				ErrCharacterNotInAlphabet,
			)
		}

		return a.set[value], nil
	}

	if value > utf8.MaxRune {
		return 0, fmt.Errorf(
			"value %d: %w",
			value,
			ErrCharacterNotInAlphabet,
		)
	}

	char := rune(value)
	if _, found := slices.BinarySearch(
		a.set,
		char,
	); !found {
		return 0, fmt.Errorf(
			"%q: %w",
			char,
			ErrCharacterNotInAlphabet,
		)
	}

	return char, nil
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
func _LookupAlphabet(
	table []*_Alphabet,
	kind StringKind,
) (*_Alphabet, error) {
	if kind < 0 || int(kind) >= len(table) {
		return nil, fmt.Errorf(
			"%d: %w",
			kind,
			ErrUnknownStringKind,
		)
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
//   - 2026-10-19 13:16: compares upper with ceil(floor/bits), so a large upper bound does not
//     wrap the product (review P5-11)
func _CharFieldAligns(
	alphabet *_Alphabet,
	upper,
	floor uint64,
) bool {
	if alphabet.bits == 0 {
		return false
	}

	// upper*bits >= floor, as upper >= ceil(floor/bits): the product can wrap.
	bitsPerChar := uint64(alphabet.bits)

	return upper >= (floor+bitsPerChar-1)/bitsPerChar
}

// _Alphabets builds one variant's table of effective alphabets.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-19 11:14: fixes UniversalString at 32 bits per character in the
//     UNALIGNED variant (review P3-3)
//   - 2026-10-19 12:59: entries for the four new clause 30.6 kinds; marks the
//     NumericString kernel alphabet (review P5-6)
func _Alphabets(variant _Variant) []*_Alphabet {
	table := make(
		[]*_Alphabet,
		STRING_KINDS,
	)

	// The clause 30.6 kinds keep the empty alphabet: they are octet strings.
	for kind := range table {
		table[kind] = new(_Alphabet)
	}

	table[STRING_IA5] = _MakeAlphabet(
		"",
		0,
		IA5_MAX,
		variant,
	)
	table[STRING_VISIBLE] = _MakeAlphabet(
		"",
		VISIBLE_MIN,
		VISIBLE_MAX,
		variant,
	)
	table[STRING_PRINTABLE] = _MakeAlphabet(
		PRINTABLE_ORDER,
		PRINTABLE_MIN,
		PRINTABLE_MAX,
		variant,
	)
	table[STRING_NUMERIC] = _MakeAlphabet(
		NUMERIC_ORDER,
		NUMERIC_MIN,
		NUMERIC_MAX,
		variant,
	)
	table[STRING_NUMERIC].nibbles = true
	table[STRING_BMP] = _MakeAlphabet(
		"",
		0,
		BMP_MAX,
		variant,
	)
	table[STRING_UNIVERSAL] = _MakeAlphabet(
		"",
		0,
		utf8.MaxRune,
		variant,
	)

	// Clause 30.5.3 gives a UniversalString 32 bits per character in both
	// variants, because its alphabet is 2^32 values wide. The Go rune type stops
	// at utf8.MaxRune, which would size the UNALIGNED field at 21 bits.
	table[STRING_UNIVERSAL].bits = UNIVERSAL_BITS

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
//   - 2026-10-19 12:59: takes the width from _Width, which NewAlphabet shares (review P5-8)
//   - 2026-10-19 13:03: sets ascii itself, so _Alphabets no longer loops over the table
func _MakeAlphabet(
	order string,
	lower,
	upper rune,
	variant _Variant,
) *_Alphabet {
	alphabet := &_Alphabet{
		order: order,
		lower: lower,
		upper: upper,
		count: uint64(upper-lower) + 1,
		known: true,
		ascii: upper < utf8.RuneSelf,
	}

	if order != "" {
		alphabet.count = uint64(len(order))
		alphabet.index = _MakeIndex(order)
	}

	// Clause 30.4.2: B is the smallest width that can number the alphabet, and
	// the ALIGNED variant rounds B up to a power of two.
	width := _Width(
		alphabet.count,
		variant,
	)
	alphabet.bits = width

	// Clause 30.4.4: the characters keep their own values if the largest fits in
	// the width, and are renumbered from zero if it does not.
	alphabet.compact = width < UINT64_BITS && uint64(upper) > uint64(1)<<width-1

	return alphabet
}
