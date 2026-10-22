package per

import (
	"fmt"
)

// CharacterString is the general case of CHARACTER STRING, X.691 31.3: the SEQUENCE of X.680
// 44.5 without data-value-descriptor. StringValue holds the octets of the complete encoding of
// the character string value (X.680 44.3 a).
//
// The predefined case, X.691 31.2, is Encoder.EncodeOctetString of the string value with an
// unconstrained size.
type CharacterString struct {
	Identification *Identification
	StringValue    []byte
}

// EncodeCharacterString encodes the general case of CHARACTER STRING, X.691 31.3: the
// identification CHOICE, then the string value as an OCTET STRING with no size constraint. The
// data-value-descriptor is absent in 31.3, so there is no preamble (19.2). A nil value or
// identification is ErrNilValue, before the first write.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) EncodeCharacterString(value *CharacterString) error {
	if value == nil {
		return fmt.Errorf(
			"character string: %w",
			ErrNilValue,
		)
	}

	if err := _CheckIdentification(value.Identification); err != nil {
		return err
	}

	// identification, X.680 44.5 and X.691 23.
	if err := e.EncodeIdentification(value.Identification); err != nil {
		return err
	}

	// string-value OCTET STRING, X.691 17.8.
	return e.EncodeOctetString(
		value.StringValue,
		CONSTRAINT_PDV_OCTETS,
	)
}

// DecodeCharacterString decodes the general case of CHARACTER STRING, X.691 31.3.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) DecodeCharacterString() (*CharacterString, error) {
	// identification, X.680 44.5 and X.691 23.
	identification, err := d.DecodeIdentification()
	if err != nil {
		return nil, err
	}

	// string-value OCTET STRING, X.691 17.8.
	data, err := d.DecodeOctetString(CONSTRAINT_PDV_OCTETS)
	if err != nil {
		return nil, err
	}

	return &CharacterString{
		Identification: identification,
		StringValue:    data,
	}, nil
}
