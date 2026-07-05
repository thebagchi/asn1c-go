package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// YearMonthEncoding is the X.691 (02/2021) clause 32.2.5 YEAR-MONTH-ENCODING
// type, used to PER-encode a DATE-family TIME value whose abstract values
// have one of the "Basic=Date Date=YM Year=Basic" or "Basic=Date Date=YM
// Year=Proleptic" property settings (X.691 Table 2, row 5).
//
//	YEAR-MONTH-ENCODING ::= SEQUENCE {
//	    year  YEAR-ENCODING,
//	    month INTEGER (1..12) -- 4 bits
//	}
//
// The YEAR-ENCODING is set according to clause 32.2.3 and the month integer
// value set to the month component of the abstract value. This is
// optimized to provide a 10-bit or 14-bit encoding in common cases.
type YearMonthEncoding struct {
	Year  *YearEncoding `per:""`
	Month int64         `per:"lb=1,ub=12"`
}

// MarshalPER encodes the YearMonthEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (y *YearMonthEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year YEAR-ENCODING
	if _, err := y.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	lb, ub := int64(1), int64(12)
	if err := encoder.EncodeInteger(y.Month, &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearMonthEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearMonthEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return y.MarshalPER(encoder)
}

// MarshalUPER encodes the YearMonthEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearMonthEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return y.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearMonthEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (y *YearMonthEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year YEAR-ENCODING
	y.Year = &YearEncoding{}
	if err := y.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	lb, ub := int64(1), int64(12)
	month, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	y.Month = month

	return nil
}

// UnmarshalAPER decodes the YearMonthEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearMonthEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return y.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearMonthEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearMonthEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return y.UnmarshalPER(decoder)
}
