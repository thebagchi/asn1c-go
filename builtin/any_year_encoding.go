package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// AnyYearEncoding is the X.691 (02/2021) clause 32.2.4 ANY-YEAR-ENCODING
// type, used to PER-encode the year component of a DATE-family TIME value
// whose abstract values have one of the "Basic=Date Date=Y Year=Negative" or
// "Basic=Date Date=Y Year=Ln" (for any n) property settings (X.691 Table 2,
// row 4), and as the "year" component of the ANY-* SEQUENCE encodings
// (ANY-YEAR-MONTH-ENCODING, ANY-DATE-ENCODING, ANY-YEAR-DAY-ENCODING,
// ANY-YEAR-WEEK-ENCODING, ANY-YEAR-WEEK-DAY-ENCODING).
//
//	ANY-YEAR-ENCODING ::= INTEGER (MIN..MAX)
//
// The integer value is set to the year component of the abstract value.
type AnyYearEncoding int64

// MarshalPER encodes the AnyYearEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (a *AnyYearEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// ANY-YEAR-ENCODING ::= INTEGER (MIN..MAX) — unconstrained
	if err := encoder.EncodeInteger(int64(*a), CONSTRAINT_UNCONSTRAINED); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the AnyYearEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (a *AnyYearEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return a.MarshalPER(encoder)
}

// MarshalUPER encodes the AnyYearEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (a *AnyYearEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return a.MarshalPER(encoder)
}

// UnmarshalPER decodes the AnyYearEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (a *AnyYearEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// ANY-YEAR-ENCODING ::= INTEGER (MIN..MAX) — unconstrained
	value, err := decoder.DecodeInteger(CONSTRAINT_UNCONSTRAINED)
	if err != nil {
		return err
	}

	*a = AnyYearEncoding(value)

	return nil
}

// UnmarshalAPER decodes the AnyYearEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (a *AnyYearEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return a.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the AnyYearEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (a *AnyYearEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return a.UnmarshalPER(decoder)
}
