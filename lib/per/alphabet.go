package per

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"unicode/utf8"
)

// Sentinel errors for the permitted alphabet of X.691 clause 30.5.
var (
	ErrNilAlphabet        = errors.New("alphabet is nil")
	ErrEmptyAlphabet      = errors.New("alphabet has no characters")
	ErrNotKnownMultiplier = errors.New("string kind is not a known-multiplier type")
)

// Alphabet is the effective permitted alphabet of a known-multiplier type after a
// FROM constraint (X.691 clauses 10.3.11, 10.3.12 and 30.5).
//
// NewAlphabet resolves the width and the numbering of both PER variants once, so a
// codec call only looks characters up. An Alphabet never changes after
// NewAlphabet returns, so goroutines can share one.
type Alphabet struct {
	aligned   *_Alphabet
	unaligned *_Alphabet
}

// NewAlphabet builds the alphabet of FROM(chars) on kind.
//
// chars is a set: the order of its characters and any repeat do not matter, and X.680
// clause 43 gives the canonical order that clause 30.5.4 numbers them in. NewAlphabet
// refuses a kind that is not a known-multiplier type (clause 30.1: only these types
// have a PER-visible alphabet), an empty set, text that is not well-formed UTF-8,
// and a character that the type does not have (ErrCharacterNotInAlphabet).
//
// A FROM constraint that is extensible is not PER-visible (clause 10.3.11): the
// caller then uses EncodeRestrictedString with the parent kind.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-7, P5-8)
func NewAlphabet(
	kind StringKind,
	chars string,
) (*Alphabet, error) {
	parent, err := _LookupAlphabet(
		ALPHABET_UNALIGNED,
		kind,
	)
	if err != nil {
		return nil, err
	}

	if !parent.known {
		return nil, fmt.Errorf(
			"%d: %w",
			kind,
			ErrNotKnownMultiplier,
		)
	}

	set, err := _PermittedSet(
		parent,
		chars,
	)
	if err != nil {
		return nil, err
	}

	return &Alphabet{
		aligned: _MakeFrom(
			set,
			VARIANT_ALIGNED,
		),
		unaligned: _MakeFrom(
			set,
			VARIANT_UNALIGNED,
		),
	}, nil
}

// EncodeAlphabetString encodes a value of a known-multiplier type with the FROM
// constraint that alphabet holds, and the SIZE constraint size, per X.691 clause 30.5.
//
// The length, the extension bit and the alignment follow the same rules as
// EncodeRestrictedString (clauses 30.4, 30.5.6, 30.5.7 and 11.9); only the width and
// the numbering of the characters come from alphabet. A character outside alphabet
// gives ErrCharacterNotInAlphabet.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-7)
func (e *Encoder) EncodeAlphabetString(
	value string,
	alphabet *Alphabet,
	size *Constraint,
) error {
	resolved, err := e._Resolved(alphabet)
	if err != nil {
		return err
	}

	return e._EncodeKnown(
		value,
		resolved,
		size,
	)
}

// DecodeAlphabetString decodes a value of the type that EncodeAlphabetString
// encodes.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-7)
func (d *Decoder) DecodeAlphabetString(
	alphabet *Alphabet,
	size *Constraint,
) (string, error) {
	resolved, err := d._Resolved(alphabet)
	if err != nil {
		return "", err
	}

	return d._DecodeKnown(
		resolved,
		size,
	)
}

// _Resolved returns the form of alphabet for this encoder's PER variant, or an
// error for a nil Alphabet.
//
// Revisions:
//   - 2026-10-19 13:02: initial creation
func (e *Encoder) _Resolved(alphabet *Alphabet) (*_Alphabet, error) {
	if alphabet == nil {
		return nil, ErrNilAlphabet
	}

	if e.aligned {
		return alphabet.aligned, nil
	}

	return alphabet.unaligned, nil
}

// _Resolved returns the form of alphabet for this decoder's PER variant, or an
// error for a nil Alphabet.
//
// Revisions:
//   - 2026-10-19 13:02: initial creation
func (d *Decoder) _Resolved(alphabet *Alphabet) (*_Alphabet, error) {
	if alphabet == nil {
		return nil, ErrNilAlphabet
	}

	if d.aligned {
		return alphabet.aligned, nil
	}

	return alphabet.unaligned, nil
}

// _PermittedSet turns the text of a FROM constraint into the sorted set of its
// characters, and checks each one against the parent alphabet.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation
func _PermittedSet(
	parent *_Alphabet,
	chars string,
) ([]rune, error) {
	if !utf8.ValidString(chars) {
		return nil, ErrInvalidUTF8
	}

	set := []rune(chars)
	if len(set) == 0 {
		return nil, ErrEmptyAlphabet
	}

	slices.Sort(set)

	set = slices.Compact(set)
	for _, char := range set {
		if _, err := parent._Value(char); err != nil {
			return nil, err
		}
	}

	return set, nil
}

// _MakeFrom derives the width and the numbering of the alphabet of a FROM set for
// one PER variant, per clauses 30.5.2 to 30.5.4. set is sorted and has no repeat.
//
// Revisions:
//   - 2026-10-19 12:59: initial creation (review P5-8)
func _MakeFrom(
	set []rune,
	variant _Variant,
) *_Alphabet {
	alphabet := &_Alphabet{
		lower: set[0],
		upper: set[len(set)-1],
		count: uint64(len(set)),
		known: true,
	}
	alphabet.bits = _Width(
		alphabet.count,
		variant,
	)
	alphabet.compact = uint64(alphabet.upper) > uint64(1)<<alphabet.bits-1
	alphabet.ascii = alphabet.upper < utf8.RuneSelf

	if alphabet.ascii {
		alphabet.order = string(set)
		alphabet.index = _MakeIndex(alphabet.order)

		return alphabet
	}

	alphabet.set = set

	return alphabet
}

// _Width returns the bits per character for count characters, per clause 30.5.2: B is
// the smallest width that numbers them, and the ALIGNED variant takes the smallest
// power of 2 not below B, which is 1 when B is 0 (a one-character alphabet).
//
// Revisions:
//   - 2026-10-19 12:59: initial creation, split out of _MakeAlphabet (review P5-8)
func _Width(
	count uint64,
	variant _Variant,
) uint8 {
	width := uint8(bits.Len64(count - 1))
	if variant == VARIANT_ALIGNED {
		if width == 0 {
			return 1
		}

		width = uint8(1) << bits.Len8(width-1)
	}

	return width
}
