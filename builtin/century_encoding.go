package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// CenturyEncoding is the X.691 (02/2021) clause 32.2.1 CENTURY-ENCODING type,
// used to PER-encode the century component of a DATE-family TIME value whose
// abstract values all have one of the "Basic=Date Date=C ..." property
// settings (X.691 Table 2, rows 1-2).
//
//	CENTURY-ENCODING ::= INTEGER (0..99) -- 7 bits
//
// The integer value is set to the value specified by the first two digits
// of the year component of the abstract value.
type CenturyEncoding int64

// MarshalPER encodes the CenturyEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (c *CenturyEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// CENTURY-ENCODING ::= INTEGER (0..99) — constrained lb=0, ub=99
	if err := encoder.EncodeInteger(int64(*c), CONSTRAINT_CENTURY); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the CenturyEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (c *CenturyEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return c.MarshalPER(encoder)
}

// MarshalUPER encodes the CenturyEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (c *CenturyEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return c.MarshalPER(encoder)
}

// UnmarshalPER decodes the CenturyEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (c *CenturyEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// CENTURY-ENCODING ::= INTEGER (0..99) — constrained lb=0, ub=99
	value, err := decoder.DecodeInteger(CONSTRAINT_CENTURY)
	if err != nil {
		return err
	}

	*c = CenturyEncoding(value)

	return nil
}

// UnmarshalAPER decodes the CenturyEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (c *CenturyEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return c.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the CenturyEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (c *CenturyEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return c.UnmarshalPER(decoder)
}
