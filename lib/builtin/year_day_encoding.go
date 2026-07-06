package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// YearDayEncoding is the X.691 (02/2021) clause 32.2.8 YEAR-DAY-ENCODING
// type, used to PER-encode a DATE-family TIME value whose abstract values
// have one of the "Basic=Date Date=YD Year=Basic" or "Basic=Date Date=YD
// Year=Proleptic" property settings (X.691 Table 2, row 9).
//
//	YEAR-DAY-ENCODING ::= SEQUENCE {
//	    year YEAR-ENCODING,
//	    day  INTEGER (1..366)
//	}
type YearDayEncoding struct {
	Year *YearEncoding `per:""`
	Day  int64         `per:"lb=1,ub=366"`
}

// MarshalPER encodes the YearDayEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (y *YearDayEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year YEAR-ENCODING
	if _, err := y.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// day INTEGER (1..366) — constrained lb=1, ub=366
	lb, ub := int64(1), int64(366)
	if err := encoder.EncodeInteger(y.Day, &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearDayEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearDayEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return y.MarshalPER(encoder)
}

// MarshalUPER encodes the YearDayEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearDayEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return y.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearDayEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (y *YearDayEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year YEAR-ENCODING
	y.Year = &YearEncoding{}
	if err := y.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// day INTEGER (1..366) — constrained lb=1, ub=366
	lb, ub := int64(1), int64(366)
	day, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	y.Day = day

	return nil
}

// UnmarshalAPER decodes the YearDayEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearDayEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return y.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearDayEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearDayEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return y.UnmarshalPER(decoder)
}
