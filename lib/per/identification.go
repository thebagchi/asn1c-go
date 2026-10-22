package per

import (
	"encoding/asn1"
	"fmt"
)

// The constraints that the types of this phase share, so that no call builds one.
// CONSTRAINT_IDENTIFICATION is the index of the CHOICE identification: six alternatives, no
// extension marker, so a 3-bit field (X.691 23.6, 11.5.7.1). CONSTRAINT_PDV_INTEGER is the
// unconstrained INTEGER of presentation-context-id (X.691 13.2.4). CONSTRAINT_PDV_OCTETS is the
// unconstrained OCTET STRING of the data value (X.691 28.3, 31.3). CONSTRAINT_PDV_ENCODING is
// the 2-bit index of the CHOICE encoding of EXTERNAL (X.691 29.1).
var (
	CONSTRAINT_IDENTIFICATION = Constrained(
		int64(IDENTIFICATION_KIND_SYNTAXES),
		int64(IDENTIFICATION_KIND_FIXED),
	)
	CONSTRAINT_PDV_INTEGER  = Unconstrained()
	CONSTRAINT_PDV_OCTETS   = Unconstrained()
	CONSTRAINT_PDV_ENCODING = Constrained(
		int64(EXTERNAL_ENCODING_KIND_SINGLE_ASN1_TYPE),
		int64(EXTERNAL_ENCODING_KIND_ARBITRARY),
	)
)

// Identification is the CHOICE identification of X.680 36.5, 37.5 and 44.5. It has no
// extension marker, so an index above 5 is an error on decode.
//
// Modeled the same way as builtin.YearEncoding: Choices holds exactly one of the six
// alternatives below.
//
// Types that are valid to be assigned to Choices:
//
//	*Identification_Syntaxes
//	*Identification_Syntax
//	*Identification_PresentationContextId
//	*Identification_ContextNegotiation
//	*Identification_TransferSyntax
//	*Identification_Fixed
type Identification struct {
	Choices _ChoiceIdentification
}

// _ChoiceIdentification is the sealed interface of the alternatives of Identification.
type _ChoiceIdentification interface {
	Kind() IdentificationKind
	_ChoiceIdentification()
}

// IdentificationKind names the alternative of Identification that is set. A value is the
// CHOICE index of the alternative, X.691 23.2.
type IdentificationKind int64

// The alternatives of Identification, in the order of X.680 36.5.
const (
	IDENTIFICATION_KIND_SYNTAXES IdentificationKind = iota
	IDENTIFICATION_KIND_SYNTAX
	IDENTIFICATION_KIND_PRESENTATION_CONTEXT_ID
	IDENTIFICATION_KIND_CONTEXT_NEGOTIATION
	IDENTIFICATION_KIND_TRANSFER_SYNTAX
	IDENTIFICATION_KIND_FIXED
)

// Identification_Syntaxes is the alternative syntaxes:
// SEQUENCE { abstract OBJECT IDENTIFIER, transfer OBJECT IDENTIFIER }.
type Identification_Syntaxes struct {
	Abstract asn1.ObjectIdentifier
	Transfer asn1.ObjectIdentifier
}

// Identification_Syntax is the alternative syntax: OBJECT IDENTIFIER.
type Identification_Syntax asn1.ObjectIdentifier

// Identification_PresentationContextId is the alternative presentation-context-id: INTEGER.
type Identification_PresentationContextId int64

// Identification_ContextNegotiation is the alternative context-negotiation:
// SEQUENCE { presentation-context-id INTEGER, transfer-syntax OBJECT IDENTIFIER }.
type Identification_ContextNegotiation struct {
	PresentationContextId int64
	TransferSyntax        asn1.ObjectIdentifier
}

// Identification_TransferSyntax is the alternative transfer-syntax: OBJECT IDENTIFIER.
type Identification_TransferSyntax asn1.ObjectIdentifier

// Identification_Fixed is the alternative fixed: NULL.
type Identification_Fixed struct {
	// Empty
}

// Kind returns IDENTIFICATION_KIND_SYNTAXES.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_Syntaxes) Kind() IdentificationKind {
	return IDENTIFICATION_KIND_SYNTAXES
}

// Kind returns IDENTIFICATION_KIND_SYNTAX.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_Syntax) Kind() IdentificationKind {
	return IDENTIFICATION_KIND_SYNTAX
}

// Kind returns IDENTIFICATION_KIND_PRESENTATION_CONTEXT_ID.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_PresentationContextId) Kind() IdentificationKind {
	return IDENTIFICATION_KIND_PRESENTATION_CONTEXT_ID
}

// Kind returns IDENTIFICATION_KIND_CONTEXT_NEGOTIATION.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_ContextNegotiation) Kind() IdentificationKind {
	return IDENTIFICATION_KIND_CONTEXT_NEGOTIATION
}

// Kind returns IDENTIFICATION_KIND_TRANSFER_SYNTAX.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_TransferSyntax) Kind() IdentificationKind {
	return IDENTIFICATION_KIND_TRANSFER_SYNTAX
}

// Kind returns IDENTIFICATION_KIND_FIXED.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_Fixed) Kind() IdentificationKind {
	return IDENTIFICATION_KIND_FIXED
}

// Marks Identification_Syntaxes as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_Syntaxes) _ChoiceIdentification() {
	// Empty
}

// Marks Identification_Syntax as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_Syntax) _ChoiceIdentification() {
	// Empty
}

// Marks Identification_PresentationContextId as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_PresentationContextId) _ChoiceIdentification() {
	// Empty
}

// Marks Identification_ContextNegotiation as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_ContextNegotiation) _ChoiceIdentification() {
	// Empty
}

// Marks Identification_TransferSyntax as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_TransferSyntax) _ChoiceIdentification() {
	// Empty
}

// Marks Identification_Fixed as an alternative of its CHOICE.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (*Identification_Fixed) _ChoiceIdentification() {
	// Empty
}

// _CheckIdentification refuses an identification that has no alternative, or whose alternative
// is a nil pointer, with ErrNilValue. The types that carry an identification call it before
// their first write, so a refusal leaves the encoder as it was.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func _CheckIdentification(value *Identification) error {
	missing := value == nil || value.Choices == nil

	if !missing {
		switch alt := value.Choices.(type) {
		case *Identification_Syntaxes:
			missing = alt == nil
		case *Identification_Syntax:
			missing = alt == nil
		case *Identification_PresentationContextId:
			missing = alt == nil
		case *Identification_ContextNegotiation:
			missing = alt == nil
		case *Identification_TransferSyntax:
			missing = alt == nil
		case *Identification_Fixed:
			missing = alt == nil
		}
	}

	if missing {
		return fmt.Errorf(
			"identification: %w",
			ErrNilValue,
		)
	}

	return nil
}

// EncodeIdentification encodes the CHOICE identification of X.680 36.5: the index of the
// alternative in 3 bits (X.691 23.6, no extension marker), then the alternative. The index
// belongs to this type and not to the alternatives, which write their own components only.
// An alternative has no preamble: syntaxes and context-negotiation have no OPTIONAL
// component (X.691 19.2). A nil identification, or one with no alternative, is ErrNilValue.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) EncodeIdentification(value *Identification) error {
	if err := _CheckIdentification(value); err != nil {
		return err
	}

	if err := e.EncodeChoiceId(
		int64(value.Choices.Kind()),
		CONSTRAINT_IDENTIFICATION,
	); err != nil {
		return err
	}

	switch alt := value.Choices.(type) {
	case *Identification_Syntaxes:
		return e._EncodeIdentificationSyntaxes(alt)
	case *Identification_Syntax:
		return e.EncodeObjectIdentifier(asn1.ObjectIdentifier(*alt))
	case *Identification_PresentationContextId:
		return e.EncodeInteger(
			int64(*alt),
			CONSTRAINT_PDV_INTEGER,
		)
	case *Identification_ContextNegotiation:
		return e._EncodeIdentificationContextNegotiation(alt)
	case *Identification_TransferSyntax:
		return e.EncodeObjectIdentifier(asn1.ObjectIdentifier(*alt))
	case *Identification_Fixed:
		return e.EncodeNull()
	}

	return fmt.Errorf(
		"identification: %w",
		ErrNilValue,
	)
}

// _EncodeIdentificationSyntaxes encodes the alternative syntaxes, a SEQUENCE of two OBJECT
// IDENTIFIERs in the order of X.680 36.5, with no preamble.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) _EncodeIdentificationSyntaxes(value *Identification_Syntaxes) error {
	// abstract OBJECT IDENTIFIER, X.691 24.
	if err := e.EncodeObjectIdentifier(value.Abstract); err != nil {
		return err
	}

	// transfer OBJECT IDENTIFIER, X.691 24.
	return e.EncodeObjectIdentifier(value.Transfer)
}

// _EncodeIdentificationContextNegotiation encodes the alternative context-negotiation, a
// SEQUENCE of an INTEGER and an OBJECT IDENTIFIER, with no preamble.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (e *Encoder) _EncodeIdentificationContextNegotiation(
	value *Identification_ContextNegotiation,
) error {
	// presentation-context-id INTEGER, X.691 13.2.4.
	if err := e.EncodeInteger(
		value.PresentationContextId,
		CONSTRAINT_PDV_INTEGER,
	); err != nil {
		return err
	}

	// transfer-syntax OBJECT IDENTIFIER, X.691 24.
	return e.EncodeObjectIdentifier(value.TransferSyntax)
}

// DecodeIdentification decodes the CHOICE identification of X.680 36.5. An index of 6 or 7
// fits the 3-bit field but names no alternative, and the CHOICE has no extension marker
// (X.691 23.6), so it is ErrValueOutOfRange.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) DecodeIdentification() (*Identification, error) {
	index, err := d.DecodeChoiceId(CONSTRAINT_IDENTIFICATION)
	if err != nil {
		return nil, err
	}

	switch IdentificationKind(index) {
	case IDENTIFICATION_KIND_SYNTAXES:
		return d._DecodeIdentificationSyntaxes()
	case IDENTIFICATION_KIND_SYNTAX:
		return d._DecodeIdentificationSyntax()
	case IDENTIFICATION_KIND_PRESENTATION_CONTEXT_ID:
		return d._DecodeIdentificationPresentationContextId()
	case IDENTIFICATION_KIND_CONTEXT_NEGOTIATION:
		return d._DecodeIdentificationContextNegotiation()
	case IDENTIFICATION_KIND_TRANSFER_SYNTAX:
		return d._DecodeIdentificationTransferSyntax()
	case IDENTIFICATION_KIND_FIXED:
		return d._DecodeIdentificationFixed()
	}

	return nil, fmt.Errorf(
		"identification index %d: %w",
		index,
		ErrValueOutOfRange,
	)
}

// _DecodeIdentificationFixed decodes the alternative fixed: a NULL, which reads nothing. An
// error returns no identification.
//
// Revisions:
//   - 2026-10-19 15:38: initial creation
func (d *Decoder) _DecodeIdentificationFixed() (*Identification, error) {
	if err := d.DecodeNull(); err != nil {
		return nil, err
	}

	return &Identification{
		Choices: &Identification_Fixed{},
	}, nil
}

// _DecodeIdentificationSyntaxes decodes the alternative syntaxes.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeIdentificationSyntaxes() (*Identification, error) {
	// abstract OBJECT IDENTIFIER, X.691 24.
	abstract, err := d.DecodeObjectIdentifier()
	if err != nil {
		return nil, err
	}

	// transfer OBJECT IDENTIFIER, X.691 24.
	transfer, err := d.DecodeObjectIdentifier()
	if err != nil {
		return nil, err
	}

	return &Identification{
		Choices: &Identification_Syntaxes{
			Abstract: abstract,
			Transfer: transfer,
		},
	}, nil
}

// _DecodeIdentificationSyntax decodes the alternative syntax.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeIdentificationSyntax() (*Identification, error) {
	syntax, err := d.DecodeObjectIdentifier()
	if err != nil {
		return nil, err
	}

	alt := Identification_Syntax(syntax)

	return &Identification{
		Choices: &alt,
	}, nil
}

// _DecodeIdentificationPresentationContextId decodes the alternative presentation-context-id.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeIdentificationPresentationContextId() (*Identification, error) {
	id, err := d.DecodeInteger(CONSTRAINT_PDV_INTEGER)
	if err != nil {
		return nil, err
	}

	alt := Identification_PresentationContextId(id)

	return &Identification{
		Choices: &alt,
	}, nil
}

// _DecodeIdentificationContextNegotiation decodes the alternative context-negotiation.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeIdentificationContextNegotiation() (*Identification, error) {
	// presentation-context-id INTEGER, X.691 13.2.4.
	id, err := d.DecodeInteger(CONSTRAINT_PDV_INTEGER)
	if err != nil {
		return nil, err
	}

	// transfer-syntax OBJECT IDENTIFIER, X.691 24.
	transfer, err := d.DecodeObjectIdentifier()
	if err != nil {
		return nil, err
	}

	return &Identification{
		Choices: &Identification_ContextNegotiation{
			PresentationContextId: id,
			TransferSyntax:        transfer,
		},
	}, nil
}

// _DecodeIdentificationTransferSyntax decodes the alternative transfer-syntax.
//
// Revisions:
//   - 2026-10-19 15:28: initial creation
func (d *Decoder) _DecodeIdentificationTransferSyntax() (*Identification, error) {
	syntax, err := d.DecodeObjectIdentifier()
	if err != nil {
		return nil, err
	}

	alt := Identification_TransferSyntax(syntax)

	return &Identification{
		Choices: &alt,
	}, nil
}
