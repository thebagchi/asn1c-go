package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// ErrExternalIdentification is what EncodeExternal reports for an identification that X.691
// 29.4 Table 1 marks CANNOT OCCUR (syntaxes, transfer-syntax, fixed), and what DecodeExternal
// reports for an encoding that has neither direct-reference nor indirect-reference.
var (
	ErrExternalIdentification = errors.New("identification cannot be mapped to an EXTERNAL")
)

// The bits of the preamble of EXTERNAL, X.691 29.1 and 19.2: one for each OPTIONAL component,
// in the order of the SEQUENCE, the first in the most significant bit of the octet.
const (
	EXTERNAL_PREAMBLE_BITS      = 3
	EXTERNAL_PRESENT_DIRECT     = 0x80
	EXTERNAL_PRESENT_INDIRECT   = 0x40
	EXTERNAL_PRESENT_DESCRIPTOR = 0x20
	EXTERNAL_PRESENT_REFERENCES = EXTERNAL_PRESENT_DIRECT | EXTERNAL_PRESENT_INDIRECT
	EXTERNAL_NO_REFERENCE_BITS  = 0
)

// External is the type EXTERNAL, X.691 29.1: the SEQUENCE of X.208 with direct-reference,
// indirect-reference, data-value-descriptor and the encoding CHOICE. Identification stands for
// the direct-reference and indirect-reference by Table 1 of 29.4: syntax is direct only,
// presentation-context-id is indirect only, context-negotiation is both (direct is the
// transfer-syntax). DataValueDescriptor is an ObjectDescriptor, which is a GraphicString of
// clause 30.6: its octets stay as they are.
type External struct {
	Identification      *Identification
	DataValueDescriptor *string
	Encoding            *ExternalEncoding
}

// ExternalEncoding is the CHOICE encoding of X.691 29.1.
//
// Types that are valid to be assigned to Choices:
//
//	*ExternalEncoding_SingleASN1Type
//	*ExternalEncoding_OctetAligned
//	*ExternalEncoding_Arbitrary
type ExternalEncoding struct {
	Choices _ChoiceExternalEncoding
}

// _ChoiceExternalEncoding is the sealed interface of the alternatives of ExternalEncoding.
type _ChoiceExternalEncoding interface {
	Kind() ExternalEncodingKind
	_ChoiceExternalEncoding()
}

// ExternalEncodingKind names the alternative of ExternalEncoding that is set. A value is the
// CHOICE index of the alternative.
type ExternalEncodingKind int64

// The alternatives of ExternalEncoding, in the order of X.691 29.1.
const (
	EXTERNAL_ENCODING_KIND_SINGLE_ASN1_TYPE ExternalEncodingKind = iota
	EXTERNAL_ENCODING_KIND_OCTET_ALIGNED
	EXTERNAL_ENCODING_KIND_ARBITRARY
)

// ExternalEncoding_SingleASN1Type is the alternative single-ASN1-type: the complete encoding of
// the value, which the codec writes as an open type, X.691 29.9 and 11.2.
type ExternalEncoding_SingleASN1Type []byte

// ExternalEncoding_OctetAligned is the alternative octet-aligned: OCTET STRING.
type ExternalEncoding_OctetAligned []byte

// ExternalEncoding_Arbitrary is the alternative arbitrary: BIT STRING.
type ExternalEncoding_Arbitrary asn1.BitString

// Kind returns EXTERNAL_ENCODING_KIND_SINGLE_ASN1_TYPE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*ExternalEncoding_SingleASN1Type) Kind() ExternalEncodingKind {
	return EXTERNAL_ENCODING_KIND_SINGLE_ASN1_TYPE
}

// Kind returns EXTERNAL_ENCODING_KIND_OCTET_ALIGNED.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*ExternalEncoding_OctetAligned) Kind() ExternalEncodingKind {
	return EXTERNAL_ENCODING_KIND_OCTET_ALIGNED
}

// Kind returns EXTERNAL_ENCODING_KIND_ARBITRARY.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*ExternalEncoding_Arbitrary) Kind() ExternalEncodingKind {
	return EXTERNAL_ENCODING_KIND_ARBITRARY
}

// Marks ExternalEncoding_SingleASN1Type as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*ExternalEncoding_SingleASN1Type) _ChoiceExternalEncoding() {
	// Empty
}

// Marks ExternalEncoding_OctetAligned as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*ExternalEncoding_OctetAligned) _ChoiceExternalEncoding() {
	// Empty
}

// Marks ExternalEncoding_Arbitrary as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*ExternalEncoding_Arbitrary) _ChoiceExternalEncoding() {
	// Empty
}

// _ExternalReferences holds the direct-reference and the indirect-reference that Table 1 of
// X.691 29.4 derives from an identification.
type _ExternalReferences struct {
	direct      asn1.ObjectIdentifier
	indirect    int64
	hasDirect   bool
	hasIndirect bool
}

// _MapExternalReferences maps an identification to the references of EXTERNAL, X.691 29.4
// Table 1: syntax is direct only, presentation-context-id is indirect only, and
// context-negotiation is both, with the transfer-syntax as direct. The other alternatives
// CANNOT OCCUR, and give ErrExternalIdentification. The caller has checked the identification
// for nil.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func _MapExternalReferences(
	value *Identification,
	references *_ExternalReferences,
) error {
	switch alt := value.Choices.(type) {
	case *Identification_Syntax:
		references.direct = asn1.ObjectIdentifier(*alt)
		references.hasDirect = true

		return nil
	case *Identification_PresentationContextId:
		references.indirect = int64(*alt)
		references.hasIndirect = true

		return nil
	case *Identification_ContextNegotiation:
		references.direct = alt.TransferSyntax
		references.indirect = alt.PresentationContextId
		references.hasDirect = true
		references.hasIndirect = true

		return nil
	}

	return fmt.Errorf(
		"identification alternative %d: %w",
		value.Choices.Kind(),
		ErrExternalIdentification,
	)
}

// _CheckExternalEncoding refuses an encoding that is nil, has no alternative, or holds a nil
// pointer, with ErrNilValue, and an arbitrary BIT STRING that claims more bits than its octets
// hold, with ErrShortBitString (X.691 16.11).
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func _CheckExternalEncoding(value *ExternalEncoding) error {
	missing := value == nil || value.Choices == nil

	if !missing {
		switch alt := value.Choices.(type) {
		case *ExternalEncoding_SingleASN1Type:
			missing = alt == nil
		case *ExternalEncoding_OctetAligned:
			missing = alt == nil
		case *ExternalEncoding_Arbitrary:
			if alt == nil {
				missing = true

				break
			}

			var (
				bits   = asn1.BitString(*alt)
				_, err = _CheckBitmap(&bits)
			)

			return err
		}
	}

	if missing {
		return fmt.Errorf(
			"external encoding: %w",
			ErrNilValue,
		)
	}

	return nil
}

// EncodeExternal encodes EXTERNAL, X.691 29.1: a 3-bit preamble (direct-reference,
// indirect-reference, data-value-descriptor, all OPTIONAL, no extension marker, 19.2), then
// the components that are present in the order of the SEQUENCE. The identification maps to the
// references by Table 1 of 29.4. Every check comes before the first write: a nil value, an
// identification or an encoding that is missing is ErrNilValue, an identification that Table 1
// does not map is ErrExternalIdentification, a short arbitrary BIT STRING is ErrShortBitString.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) EncodeExternal(value *External) error {
	if value == nil {
		return fmt.Errorf(
			"external: %w",
			ErrNilValue,
		)
	}

	if err := _CheckIdentification(value.Identification); err != nil {
		return err
	}

	var references _ExternalReferences

	if err := _MapExternalReferences(
		value.Identification,
		&references,
	); err != nil {
		return err
	}

	if err := _CheckExternalEncoding(value.Encoding); err != nil {
		return err
	}

	if err := e._EncodeExternalPreamble(
		value,
		&references,
	); err != nil {
		return err
	}

	if err := e._EncodeExternalReferences(&references); err != nil {
		return err
	}

	// data-value-descriptor ObjectDescriptor OPTIONAL, X.680 48, GraphicString, X.691 30.6.
	if value.DataValueDescriptor != nil {
		if err := e.EncodeRestrictedString(
			*value.DataValueDescriptor,
			STRING_GRAPHIC,
			CONSTRAINT_PDV_OCTETS,
		); err != nil {
			return err
		}
	}

	return e._EncodeExternalEncoding(value.Encoding)
}

// _EncodeExternalPreamble writes the three presence bits of EXTERNAL, X.691 29.1 and 19.2.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) _EncodeExternalPreamble(
	value *External,
	references *_ExternalReferences,
) error {
	var octet [1]byte

	if references.hasDirect {
		octet[0] |= EXTERNAL_PRESENT_DIRECT
	}

	if references.hasIndirect {
		octet[0] |= EXTERNAL_PRESENT_INDIRECT
	}

	if value.DataValueDescriptor != nil {
		octet[0] |= EXTERNAL_PRESENT_DESCRIPTOR
	}

	return e.EncodePreamble(&asn1.BitString{
		Bytes:     octet[:],
		BitLength: EXTERNAL_PREAMBLE_BITS,
	})
}

// _EncodeExternalReferences writes the references that are present: direct-reference as an
// OBJECT IDENTIFIER (X.691 24), then indirect-reference as an INTEGER (X.691 13.2.4).
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) _EncodeExternalReferences(references *_ExternalReferences) error {
	// direct-reference OBJECT IDENTIFIER OPTIONAL.
	if references.hasDirect {
		if err := e.EncodeObjectIdentifier(references.direct); err != nil {
			return err
		}
	}

	// indirect-reference INTEGER OPTIONAL.
	if references.hasIndirect {
		return e.EncodeInteger(
			references.indirect,
			CONSTRAINT_PDV_INTEGER,
		)
	}

	return nil
}

// _EncodeExternalEncoding encodes the CHOICE encoding of X.691 29.1: the index in 2 bits
// (23.6, no extension marker), then single-ASN1-type as an open type (29.9, 11.2.2),
// octet-aligned as an OCTET STRING (17.8), or arbitrary as a BIT STRING (16.11). The caller
// has checked the value.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) _EncodeExternalEncoding(value *ExternalEncoding) error {
	if err := e.EncodeChoiceId(
		int64(value.Choices.Kind()),
		CONSTRAINT_PDV_ENCODING,
	); err != nil {
		return err
	}

	switch alt := value.Choices.(type) {
	case *ExternalEncoding_SingleASN1Type:
		return e.EncodeOpenType(*alt)
	case *ExternalEncoding_OctetAligned:
		return e.EncodeOctetString(
			*alt,
			CONSTRAINT_PDV_OCTETS,
		)
	case *ExternalEncoding_Arbitrary:
		bits := asn1.BitString(*alt)

		return e.EncodeBitString(
			&bits,
			CONSTRAINT_PDV_OCTETS,
		)
	}

	return fmt.Errorf(
		"external encoding: %w",
		ErrNilValue,
	)
}

// DecodeExternal decodes EXTERNAL, X.691 29.1. The presence of the two references gives the
// identification by Table 1 of 29.4: direct only is syntax, indirect only is
// presentation-context-id, both is context-negotiation. With neither, the encoding names no
// identification, and the call reports ErrExternalIdentification.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) DecodeExternal() (*External, error) {
	var octet [1]byte

	preamble := asn1.BitString{
		Bytes:     octet[:],
		BitLength: EXTERNAL_PREAMBLE_BITS,
	}

	if err := d.DecodePreamble(&preamble); err != nil {
		return nil, err
	}

	if octet[0]&EXTERNAL_PRESENT_REFERENCES == EXTERNAL_NO_REFERENCE_BITS {
		return nil, fmt.Errorf(
			"no direct-reference and no indirect-reference: %w",
			ErrExternalIdentification,
		)
	}

	identification, err := d._DecodeExternalReferences(octet[0])
	if err != nil {
		return nil, err
	}

	value := &External{
		Identification: identification,
	}

	// data-value-descriptor ObjectDescriptor OPTIONAL, X.680 48, GraphicString, X.691 30.6.
	if octet[0]&EXTERNAL_PRESENT_DESCRIPTOR != 0 {
		text, err := d.DecodeRestrictedString(
			STRING_GRAPHIC,
			CONSTRAINT_PDV_OCTETS,
		)
		if err != nil {
			return nil, err
		}

		value.DataValueDescriptor = &text
	}

	value.Encoding, err = d._DecodeExternalEncoding()
	if err != nil {
		return nil, err
	}

	return value, nil
}

// _DecodeExternalReferences reads the references that the preamble marks and builds the
// identification of Table 1, X.691 29.4.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeExternalReferences(present byte) (*Identification, error) {
	var (
		direct   asn1.ObjectIdentifier
		indirect int64
		err      error
	)

	// direct-reference OBJECT IDENTIFIER OPTIONAL.
	if present&EXTERNAL_PRESENT_DIRECT != 0 {
		direct, err = d.DecodeObjectIdentifier()
		if err != nil {
			return nil, err
		}
	}

	// indirect-reference INTEGER OPTIONAL.
	if present&EXTERNAL_PRESENT_INDIRECT != 0 {
		indirect, err = d.DecodeInteger(CONSTRAINT_PDV_INTEGER)
		if err != nil {
			return nil, err
		}
	}

	switch present & EXTERNAL_PRESENT_REFERENCES {
	case EXTERNAL_PRESENT_DIRECT:
		alt := Identification_Syntax(direct)

		return &Identification{
			Choices: &alt,
		}, nil
	case EXTERNAL_PRESENT_INDIRECT:
		alt := Identification_PresentationContextId(indirect)

		return &Identification{
			Choices: &alt,
		}, nil
	}

	return &Identification{
		Choices: &Identification_ContextNegotiation{
			PresentationContextId: indirect,
			TransferSyntax:        direct,
		},
	}, nil
}

// _DecodeExternalEncoding decodes the CHOICE encoding of X.691 29.1. An index of 3 fits the
// 2-bit field but names no alternative, and the CHOICE has no extension marker (23.6), so it
// is ErrValueOutOfRange.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeExternalEncoding() (*ExternalEncoding, error) {
	index, err := d.DecodeChoiceId(CONSTRAINT_PDV_ENCODING)
	if err != nil {
		return nil, err
	}

	switch ExternalEncodingKind(index) {
	case EXTERNAL_ENCODING_KIND_SINGLE_ASN1_TYPE:
		inner, err := d.DecodeOpenType()
		if err != nil {
			return nil, err
		}

		alt := ExternalEncoding_SingleASN1Type(inner)

		return &ExternalEncoding{
			Choices: &alt,
		}, nil
	case EXTERNAL_ENCODING_KIND_OCTET_ALIGNED:
		octets, err := d.DecodeOctetString(CONSTRAINT_PDV_OCTETS)
		if err != nil {
			return nil, err
		}

		alt := ExternalEncoding_OctetAligned(octets)

		return &ExternalEncoding{
			Choices: &alt,
		}, nil
	case EXTERNAL_ENCODING_KIND_ARBITRARY:
		bits, err := d.DecodeBitString(CONSTRAINT_PDV_OCTETS)
		if err != nil {
			return nil, err
		}

		alt := ExternalEncoding_Arbitrary(*bits)

		return &ExternalEncoding{
			Choices: &alt,
		}, nil
	}

	return nil, fmt.Errorf(
		"external encoding index %d: %w",
		index,
		ErrValueOutOfRange,
	)
}
