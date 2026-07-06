package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// YearWeekDayEncoding is the X.691 (02/2021) clause 32.2.12
// YEAR-WEEK-DAY-ENCODING type, used to PER-encode a DATE-family TIME value
// whose abstract values have one of the "Basic=Date Date=YWD Year=Basic" or
// "Basic=Date Date=YWD Year=Proleptic" property settings (X.691 Table 2,
// row 13).
//
//	YEAR-WEEK-DAY-ENCODING ::= SEQUENCE {
//	    year YEAR-ENCODING,
//	    week INTEGER (1..53), -- 6 bits
//	    day  INTEGER (1..7)   -- 3 bits
//	}
//
// This is optimized to provide a 15-bit or 19-bit encoding in common cases.
type YearWeekDayEncoding struct {
	Year *YearEncoding `per:""`
	Week int64         `per:"lb=1,ub=53"`
	Day  int64         `per:"lb=1,ub=7"`
}

// MarshalPER encodes the YearWeekDayEncoding using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (y *YearWeekDayEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year YEAR-ENCODING
	if _, err := y.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// week INTEGER (1..53) — constrained lb=1, ub=53
	{
		lb, ub := int64(1), int64(53)
		if err := encoder.EncodeInteger(y.Week, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// day INTEGER (1..7) — constrained lb=1, ub=7
	{
		lb, ub := int64(1), int64(7)
		if err := encoder.EncodeInteger(y.Day, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearWeekDayEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearWeekDayEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return y.MarshalPER(encoder)
}

// MarshalUPER encodes the YearWeekDayEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearWeekDayEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return y.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearWeekDayEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (y *YearWeekDayEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year YEAR-ENCODING
	y.Year = &YearEncoding{}
	if err := y.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// week INTEGER (1..53) — constrained lb=1, ub=53
	{
		lb, ub := int64(1), int64(53)
		week, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		y.Week = week
	}

	// day INTEGER (1..7) — constrained lb=1, ub=7
	{
		lb, ub := int64(1), int64(7)
		day, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		y.Day = day
	}

	return nil
}

// UnmarshalAPER decodes the YearWeekDayEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearWeekDayEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return y.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearWeekDayEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearWeekDayEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return y.UnmarshalPER(decoder)
}
