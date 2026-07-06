package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// AnyYearWeekEncoding is the X.691 (02/2021) clause 32.2.11
// ANY-YEAR-WEEK-ENCODING type, used to PER-encode a DATE-family TIME value
// whose abstract values have one of the "Basic=Date Date=YW Year=Negative"
// or "Basic=Date Date=YW Year=Ln" (for any n) property settings (X.691
// Table 2, row 12).
//
//	ANY-YEAR-WEEK-ENCODING ::= SEQUENCE {
//	    year ANY-YEAR-ENCODING,
//	    week INTEGER (1..53)
//	}
type AnyYearWeekEncoding struct {
	Year AnyYearEncoding `per:""`
	Week int64           `per:"lb=1,ub=53"`
}

// MarshalPER encodes the AnyYearWeekEncoding using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (a *AnyYearWeekEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year ANY-YEAR-ENCODING
	if _, err := a.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// week INTEGER (1..53) — constrained lb=1, ub=53
	lb, ub := int64(1), int64(53)
	if err := encoder.EncodeInteger(a.Week, &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the AnyYearWeekEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyYearWeekEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return a.MarshalPER(encoder)
}

// MarshalUPER encodes the AnyYearWeekEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyYearWeekEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return a.MarshalPER(encoder)
}

// UnmarshalPER decodes the AnyYearWeekEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (a *AnyYearWeekEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year ANY-YEAR-ENCODING
	if err := a.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// week INTEGER (1..53) — constrained lb=1, ub=53
	lb, ub := int64(1), int64(53)
	week, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	a.Week = week

	return nil
}

// UnmarshalAPER decodes the AnyYearWeekEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyYearWeekEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return a.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the AnyYearWeekEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyYearWeekEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return a.UnmarshalPER(decoder)
}
