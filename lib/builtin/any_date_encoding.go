package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// AnyDateEncoding is the X.691 (02/2021) clause 32.2.7 ANY-DATE-ENCODING
// type, used to PER-encode a DATE-family TIME value whose abstract values
// have one of the "Basic=Date Date=YMD Year=Negative" or "Basic=Date
// Date=YMD Year=Ln" (for any n) property settings (X.691 Table 2, row 8).
//
//	ANY-DATE-ENCODING ::= SEQUENCE {
//	    year  ANY-YEAR-ENCODING,
//	    month INTEGER (1..12),
//	    day   INTEGER (1..31)
//	}
type AnyDateEncoding struct {
	Year  AnyYearEncoding `per:""`
	Month int64           `per:"lb=1,ub=12"`
	Day   int64           `per:"lb=1,ub=31"`
}

// MarshalPER encodes the AnyDateEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (a *AnyDateEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// year ANY-YEAR-ENCODING
	if _, err := a.Year.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	{
		lb, ub := int64(1), int64(12)
		if err := encoder.EncodeInteger(a.Month, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// day INTEGER (1..31) — constrained lb=1, ub=31
	{
		lb, ub := int64(1), int64(31)
		if err := encoder.EncodeInteger(a.Day, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the AnyDateEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyDateEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return a.MarshalPER(encoder)
}

// MarshalUPER encodes the AnyDateEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyDateEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return a.MarshalPER(encoder)
}

// UnmarshalPER decodes the AnyDateEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (a *AnyDateEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// year ANY-YEAR-ENCODING
	if err := a.Year.UnmarshalPER(decoder); err != nil {
		return err
	}

	// month INTEGER (1..12) — constrained lb=1, ub=12
	{
		lb, ub := int64(1), int64(12)
		month, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		a.Month = month
	}

	// day INTEGER (1..31) — constrained lb=1, ub=31
	{
		lb, ub := int64(1), int64(31)
		day, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		a.Day = day
	}

	return nil
}

// UnmarshalAPER decodes the AnyDateEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyDateEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return a.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the AnyDateEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyDateEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return a.UnmarshalPER(decoder)
}
