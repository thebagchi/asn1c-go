package per

import (
	"encoding/asn1"
	"fmt"
)

// InstanceOf is the associated type of INSTANCE OF, X.681 C.7: SEQUENCE { type-id &id, value
// [0] &Type } in EXPLICIT tags. Value holds the complete encoding of the &Type value, which the
// codec writes as an open type, X.691 11.2.
type InstanceOf struct {
	TypeID asn1.ObjectIdentifier
	Value  []byte
}

// EncodeInstanceOf encodes the associated type of INSTANCE OF, X.681 C.7: type-id as an OBJECT
// IDENTIFIER (X.691 24), then value as an open type (X.691 11.2.2). The SEQUENCE has no
// OPTIONAL component and no extension marker, so no preamble (19.2), and the EXPLICIT tag is
// not part of PER. A nil value is ErrNilValue, before the first write.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) EncodeInstanceOf(value *InstanceOf) error {
	if value == nil {
		return fmt.Errorf(
			"instance of: %w",
			ErrNilValue,
		)
	}

	// type-id &id, X.691 24.
	if err := e.EncodeObjectIdentifier(value.TypeID); err != nil {
		return err
	}

	// value [0] &Type, an open type, X.691 11.2.
	return e.EncodeOpenType(value.Value)
}

// DecodeInstanceOf decodes the associated type of INSTANCE OF, X.681 C.7. Value is a copy of
// the octets of the open type.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) DecodeInstanceOf() (*InstanceOf, error) {
	// type-id &id, X.691 24.
	id, err := d.DecodeObjectIdentifier()
	if err != nil {
		return nil, err
	}

	// value [0] &Type, an open type, X.691 11.2.
	inner, err := d.DecodeOpenType()
	if err != nil {
		return nil, err
	}

	return &InstanceOf{
		TypeID: id,
		Value:  inner,
	}, nil
}
