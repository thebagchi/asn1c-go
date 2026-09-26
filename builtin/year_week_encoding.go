package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// YearWeekEncoding is the X.691 (02/2021) clause 32.2.10 YEAR-WEEK-ENCODING
// type, used to PER-encode a DATE-family TIME value whose abstract values
// have one of the "Basic=Date Date=YW Year=Basic" or "Basic=Date Date=YW
// Year=Proleptic" property settings (X.691 Table 2, row 11).
//
//	YEAR-WEEK-ENCODING ::= SEQUENCE {
//	    year YEAR-ENCODING,
//	    week INTEGER (1..53) -- 6 bits
//	}
//
// This is optimized to provide a 12-bit or 16-bit encoding in common cases.
type YearWeekEncoding struct {
	Year *YearEncoding `per:""`
	Week int64         `per:"lb=1,ub=53"`
}

// MarshalPER encodes the YearWeekEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (y *YearWeekEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year YEAR-ENCODING
	if _, err := y.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// week INTEGER (1..53) — constrained lb=1, ub=53
	if err := encoder.EncodeInteger(y.Week, CONSTRAINT_WEEK); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearWeekEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (y *YearWeekEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return y.MarshalPER(encoder)
}

// MarshalUPER encodes the YearWeekEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (y *YearWeekEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return y.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearWeekEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (y *YearWeekEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year YEAR-ENCODING
	y.Year = &YearEncoding{}
	if err := y.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// week INTEGER (1..53) — constrained lb=1, ub=53
	week, err := decoder.DecodeInteger(CONSTRAINT_WEEK)
	if err != nil {
		return err
	}

	y.Week = week

	return nil
}

// UnmarshalAPER decodes the YearWeekEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (y *YearWeekEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return y.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearWeekEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (y *YearWeekEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return y.UnmarshalPER(decoder)
}
