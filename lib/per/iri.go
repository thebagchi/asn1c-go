package per

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrIRIText is reported for contents octets that are not UTF-8.
var (
	ErrIRIText = errors.New("iri contents are not valid UTF-8")
)

// EncodeIRI encodes an OID-IRI, per X.691 clause 26: the contents octets of its
// BER encoding behind a length determinant. Those octets are the UTF-8 of the
// value text, with its leading "/" (X.690 clause 8.21.2). PER does not check the
// syntax of the labels (X.680 clause 34.3); text that is not valid UTF-8 gives
// ErrIRIText.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-2)
func (e *Encoder) EncodeIRI(value string) error {
	return e._EncodeIRI(value)
}

// DecodeIRI reads an OID-IRI, per X.691 clause 26. The result is the one
// allocation of the string. Contents that are not valid UTF-8 give ErrIRIText.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-2)
func (d *Decoder) DecodeIRI() (string, error) {
	return d._DecodeIRI()
}

// EncodeRelativeIRI encodes a RELATIVE-OID-IRI, per X.691 clause 27: the UTF-8
// of the value text behind a length determinant (X.690 clause 8.22.2). PER does
// not check the syntax of the labels (X.680 clause 35.3); text that is not valid
// UTF-8 gives ErrIRIText.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-2)
func (e *Encoder) EncodeRelativeIRI(value string) error {
	return e._EncodeIRI(value)
}

// DecodeRelativeIRI reads a RELATIVE-OID-IRI, per X.691 clause 27. The result is
// the one allocation of the string. Contents that are not valid UTF-8 give
// ErrIRIText.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-2)
func (d *Decoder) DecodeRelativeIRI() (string, error) {
	return d._DecodeIRI()
}

// _EncodeIRI writes the octets of value behind an unconstrained length
// determinant, which is what clauses 26 and 27 of X.691 ask for both types.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-2)
func (e *Encoder) _EncodeIRI(value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf(
			"text of %d octets: %w",
			len(value),
			ErrIRIText,
		)
	}

	return e.EncodeOctetString(
		_StringBytes(value),
		Unconstrained(),
	)
}

// _DecodeIRI reads the contents octets and copies them into a string once.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-2)
func (d *Decoder) _DecodeIRI() (string, error) {
	contents, err := d._DecodeContents()
	if err != nil {
		return "", err
	}

	if !utf8.Valid(contents) {
		return "", fmt.Errorf(
			"contents of %d octets: %w",
			len(contents),
			ErrIRIText,
		)
	}

	return string(contents), nil
}
