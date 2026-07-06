package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// AnyYearDayEncoding is the X.691 (02/2021) clause 32.2.9
// ANY-YEAR-DAY-ENCODING type, used to PER-encode a DATE-family TIME value
// whose abstract values have one of the "Basic=Date Date=YD Year=Negative"
// or "Basic=Date Date=YD Year=Ln" (for any n) property settings (X.691
// Table 2, row 10).
//
//	ANY-YEAR-DAY-ENCODING ::= SEQUENCE {
//	    year ANY-YEAR-ENCODING,
//	    day  INTEGER (1..366)
//	}
type AnyYearDayEncoding struct {
	Year AnyYearEncoding `per:""`
	Day  int64           `per:"lb=1,ub=366"`
}

// MarshalPER encodes the AnyYearDayEncoding using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (a *AnyYearDayEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year ANY-YEAR-ENCODING
	if _, err := a.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// day INTEGER (1..366) — constrained lb=1, ub=366
	lb, ub := int64(1), int64(366)
	if err := encoder.EncodeInteger(a.Day, &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the AnyYearDayEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyYearDayEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return a.MarshalPER(encoder)
}

// MarshalUPER encodes the AnyYearDayEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyYearDayEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return a.MarshalPER(encoder)
}

// UnmarshalPER decodes the AnyYearDayEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (a *AnyYearDayEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year ANY-YEAR-ENCODING
	if err := a.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// day INTEGER (1..366) — constrained lb=1, ub=366
	lb, ub := int64(1), int64(366)
	day, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	a.Day = day

	return nil
}

// UnmarshalAPER decodes the AnyYearDayEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyYearDayEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return a.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the AnyYearDayEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyYearDayEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return a.UnmarshalPER(decoder)
}
