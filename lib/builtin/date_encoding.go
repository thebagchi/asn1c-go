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
func (d *DateEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year YEAR-ENCODING
	if _, err := d.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	{
		lb, ub := int64(1), int64(12)
		if err := encoder.EncodeInteger(d.Month, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// day INTEGER (1..31) — constrained lb=1, ub=31
	{
		lb, ub := int64(1), int64(31)
		if err := encoder.EncodeInteger(d.Day, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DateEncoding using Aligned Packed Encoding Rules (APER).
func (d *DateEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return d.MarshalPER(encoder)
}

// MarshalUPER encodes the DateEncoding using Unaligned Packed Encoding Rules (UPER).
func (d *DateEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return d.MarshalPER(encoder)
}

// UnmarshalPER decodes the DateEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (d *DateEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year YEAR-ENCODING
	d.Year = &YearEncoding{}
	if err := d.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	{
		lb, ub := int64(1), int64(12)
		month, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		d.Month = month
	}

	// day INTEGER (1..31) — constrained lb=1, ub=31
	{
		lb, ub := int64(1), int64(31)
		day, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		d.Day = day
	}

	return nil
}

// UnmarshalAPER decodes the DateEncoding using Aligned Packed Encoding Rules (APER).
func (d *DateEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return d.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DateEncoding using Unaligned Packed Encoding Rules (UPER).
func (d *DateEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return d.UnmarshalPER(decoder)
}
