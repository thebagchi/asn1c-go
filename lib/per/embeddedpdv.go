package per

import (
	"fmt"
)

// EmbeddedPDV is the general case of EMBEDDED PDV, X.691 28.3: the SEQUENCE of X.680 36.5
// without data-value-descriptor, so with no preamble bit. DataValue holds the octets of the
// complete encoding of the single data value (X.680 36.3 a).
//
// The predefined case, X.691 28.2 (identification constrained to fixed or syntaxes to one
// value), is not this type: it is Encoder.EncodeOctetString of the data value with an
// unconstrained size.
type EmbeddedPDV struct {
	Identification *Identification
	DataValue      []byte
}

// EncodeEmbeddedPDV encodes the general case of EMBEDDED PDV, X.691 28.3: the identification
// CHOICE, then the data value as an OCTET STRING with no size constraint. The data-value-
// descriptor is absent in 28.3, so the SEQUENCE has no OPTIONAL component and no preamble
// (19.2). A nil value or identification is ErrNilValue, before the first write.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) EncodeEmbeddedPDV(value *EmbeddedPDV) error {
	if value == nil {
		return fmt.Errorf(
			"embedded pdv: %w",
			ErrNilValue,
		)
	}

	if err := _CheckIdentification(value.Identification); err != nil {
		return err
	}

	// identification, X.680 36.5 and X.691 23.
	if err := e.EncodeIdentification(value.Identification); err != nil {
		return err
	}

	// data-value OCTET STRING, X.691 17.8.
	return e.EncodeOctetString(
		value.DataValue,
		CONSTRAINT_PDV_OCTETS,
	)
}

// DecodeEmbeddedPDV decodes the general case of EMBEDDED PDV, X.691 28.3.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) DecodeEmbeddedPDV() (*EmbeddedPDV, error) {
	// identification, X.680 36.5 and X.691 23.
	identification, err := d.DecodeIdentification()
	if err != nil {
		return nil, err
	}

	// data-value OCTET STRING, X.691 17.8.
	data, err := d.DecodeOctetString(CONSTRAINT_PDV_OCTETS)
	if err != nil {
		return nil, err
	}

	return &EmbeddedPDV{
		Identification: identification,
		DataValue:      data,
	}, nil
}
