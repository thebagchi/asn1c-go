package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// TimeOfDayUtcEncoding is the X.691 (02/2021) clause 32.3
// TIME-OF-DAY-UTC-ENCODING type, used to PER-encode a TIME-family value
// whose abstract values have the "Basic=Time Time=HMS Local-or-UTC=Z"
// property setting.
//
//	TIME-OF-DAY-UTC-ENCODING ::= SEQUENCE {
//	    hours   INTEGER (0..24), -- 5 bits
//	    minutes INTEGER (0..59), -- 5 bits
//	    seconds INTEGER (0..60)  -- 5 bits
//	}
//
// This is optimized to provide a 15-bit encoding.
type TimeOfDayUtcEncoding struct {
	Hours   int64 `per:"lb=0,ub=24"`
	Minutes int64 `per:"lb=0,ub=59"`
	Seconds int64 `per:"lb=0,ub=60"`
}

// MarshalPER encodes the TimeOfDayUtcEncoding using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (t *TimeOfDayUtcEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		if err := encoder.EncodeInteger(t.Hours, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	{
		lb, ub := int64(0), int64(59)
		if err := encoder.EncodeInteger(t.Minutes, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// seconds INTEGER (0..60) — constrained lb=0, ub=60
	{
		lb, ub := int64(0), int64(60)
		if err := encoder.EncodeInteger(t.Seconds, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeOfDayUtcEncoding using Aligned Packed Encoding Rules (APER).
func (t *TimeOfDayUtcEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return t.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayUtcEncoding using Unaligned Packed Encoding Rules (UPER).
func (t *TimeOfDayUtcEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return t.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayUtcEncoding using Packed Encoding
// Rules from decoder, so nested types can chain decoding off a shared
// decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (t *TimeOfDayUtcEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		hours, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		t.Hours = hours
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	{
		lb, ub := int64(0), int64(59)
		minutes, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		t.Minutes = minutes
	}

	// seconds INTEGER (0..60) — constrained lb=0, ub=60
	{
		lb, ub := int64(0), int64(60)
		seconds, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		t.Seconds = seconds
	}

	return nil
}

// UnmarshalAPER decodes the TimeOfDayUtcEncoding using Aligned Packed Encoding Rules (APER).
func (t *TimeOfDayUtcEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return t.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayUtcEncoding using Unaligned Packed Encoding Rules (UPER).
func (t *TimeOfDayUtcEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return t.UnmarshalPER(decoder)
}
