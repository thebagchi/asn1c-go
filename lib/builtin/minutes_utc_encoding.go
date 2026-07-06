package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// MinutesUtcEncoding is the X.691 (02/2021) clause 32.3
// MINUTES-UTC-ENCODING type, used to PER-encode a TIME-family value whose
// abstract values have the "Basic=Time Time=HM Local-or-UTC=Z" property
// setting.
//
//	MINUTES-UTC-ENCODING ::= SEQUENCE {
//	    hours   INTEGER (0..24), -- 5 bits
//	    minutes INTEGER (0..59)  -- 5 bits
//	}
//
// This is optimized to provide a 10-bit encoding.
type MinutesUtcEncoding struct {
	Hours   int64 `per:"lb=0,ub=24"`
	Minutes int64 `per:"lb=0,ub=59"`
}

// MarshalPER encodes the MinutesUtcEncoding using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (m *MinutesUtcEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		if err := encoder.EncodeInteger(m.Hours, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	{
		lb, ub := int64(0), int64(59)
		if err := encoder.EncodeInteger(m.Minutes, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the MinutesUtcEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesUtcEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return m.MarshalPER(encoder)
}

// MarshalUPER encodes the MinutesUtcEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesUtcEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return m.MarshalPER(encoder)
}

// UnmarshalPER decodes the MinutesUtcEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (m *MinutesUtcEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		hours, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		m.Hours = hours
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	{
		lb, ub := int64(0), int64(59)
		minutes, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		m.Minutes = minutes
	}

	return nil
}

// UnmarshalAPER decodes the MinutesUtcEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesUtcEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return m.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the MinutesUtcEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesUtcEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return m.UnmarshalPER(decoder)
}
