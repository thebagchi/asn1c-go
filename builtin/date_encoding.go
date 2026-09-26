package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// DateEncoding is the X.691 (02/2021) clause 32.2.6 DATE-ENCODING type, used
// to PER-encode a DATE-family TIME value whose abstract values have one of
// the "Basic=Date Date=YMD Year=Basic" or "Basic=Date Date=YMD
// Year=Proleptic" property settings (X.691 Table 2, row 7).
//
//	DATE-ENCODING ::= SEQUENCE {
//	    year  YEAR-ENCODING,
//	    month INTEGER (1..12), -- 4 bits
//	    day   INTEGER (1..31)  -- 5 bits
//	}
//
// The YEAR-ENCODING is set according to clause 32.2.3 and the month/day
// integers set to the month/day components of the abstract value. This is
// optimized to provide a 15-bit or 19-bit encoding in common cases.
type DateEncoding struct {
	Year  *YearEncoding `per:""`
	Month int64         `per:"lb=1,ub=12"`
	Day   int64         `per:"lb=1,ub=31"`
}

// MarshalPER encodes the DateEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DateEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year YEAR-ENCODING
	if _, err := d.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	if err := encoder.EncodeInteger(d.Month, CONSTRAINT_MONTH); err != nil {
		return nil, err
	}

	// day INTEGER (1..31) — constrained lb=1, ub=31
	if err := encoder.EncodeInteger(d.Day, CONSTRAINT_DAY_OF_MONTH); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DateEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DateEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return d.MarshalPER(encoder)
}

// MarshalUPER encodes the DateEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DateEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return d.MarshalPER(encoder)
}

// UnmarshalPER decodes the DateEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DateEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year YEAR-ENCODING
	d.Year = &YearEncoding{}
	if err := d.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	month, err := decoder.DecodeInteger(CONSTRAINT_MONTH)
	if err != nil {
		return err
	}

	d.Month = month

	// day INTEGER (1..31) — constrained lb=1, ub=31
	day, err := decoder.DecodeInteger(CONSTRAINT_DAY_OF_MONTH)
	if err != nil {
		return err
	}

	d.Day = day

	return nil
}

// UnmarshalAPER decodes the DateEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DateEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return d.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DateEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DateEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return d.UnmarshalPER(decoder)
}
