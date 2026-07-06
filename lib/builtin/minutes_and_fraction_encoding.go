package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// MinutesAndFractionEncoding is the X.691 (02/2021) clause 32.3
// MINUTES-AND-FRACTION-ENCODING type, used to PER-encode a TIME-family
// value whose abstract values have the "Basic=Time Time=HMF3
// Local-or-UTC=L" property setting.
//
//	MINUTES-AND-FRACTION-ENCODING ::= SEQUENCE {
//	    hours    INTEGER (0..24), -- 5 bits
//	    minutes  INTEGER (0..59), -- 5 bits
//	    fraction INTEGER (0..999, ..., 1000..MAX) -- 11 bits for up to 3-digit accuracy
//	}
//
// This is optimized to provide a 21-bit encoding for up to 3-digit
// accuracy.
type MinutesAndFractionEncoding struct {
	Hours    int64 `per:"lb=0,ub=24"`
	Minutes  int64 `per:"lb=0,ub=59"`
	Fraction int64 `per:"lb=0,ub=999,ext"`
}

// MarshalPER encodes the MinutesAndFractionEncoding using Packed Encoding
// Rules onto encoder, so nested types can chain encoding onto a shared
// encoder. MarshalAPER/MarshalUPER create the encoder and call this.
func (m *MinutesAndFractionEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
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

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		if err := encoder.EncodeInteger(m.Fraction, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the MinutesAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesAndFractionEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return m.MarshalPER(encoder)
}

// MarshalUPER encodes the MinutesAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesAndFractionEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return m.MarshalPER(encoder)
}

// UnmarshalPER decodes the MinutesAndFractionEncoding using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (m *MinutesAndFractionEncoding) UnmarshalPER(decoder *per.Decoder) error {
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

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		fraction, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		m.Fraction = fraction
	}

	return nil
}

// UnmarshalAPER decodes the MinutesAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesAndFractionEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return m.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the MinutesAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesAndFractionEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return m.UnmarshalPER(decoder)
}
