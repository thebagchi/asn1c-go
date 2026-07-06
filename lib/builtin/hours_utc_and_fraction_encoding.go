package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// HoursUtcAndFractionEncoding is the X.691 (02/2021) clause 32.3
// HOURS-UTC-AND-FRACTION-ENCODING type, used to PER-encode a TIME-family
// value whose abstract values have the "Basic=Time Time=HF3
// Local-or-UTC=Z" property setting.
//
//	HOURS-UTC-AND-FRACTION-ENCODING ::= SEQUENCE {
//	    hours    INTEGER (0..24), -- 5 bits
//	    fraction INTEGER (0..999, ..., 1000..MAX) -- 11 bits for up to 3-digit accuracy
//	}
//
// This is optimized to provide a 16-bit encoding for up to 3-digit
// accuracy.
type HoursUtcAndFractionEncoding struct {
	Hours    int64 `per:"lb=0,ub=24"`
	Fraction int64 `per:"lb=0,ub=999,ext"`
}

// MarshalPER encodes the HoursUtcAndFractionEncoding using Packed Encoding
// Rules onto encoder, so nested types can chain encoding onto a shared
// encoder. MarshalAPER/MarshalUPER create the encoder and call this.
func (h *HoursUtcAndFractionEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		if err := encoder.EncodeInteger(h.Hours, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		if err := encoder.EncodeInteger(h.Fraction, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the HoursUtcAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursUtcAndFractionEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return h.MarshalPER(encoder)
}

// MarshalUPER encodes the HoursUtcAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursUtcAndFractionEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return h.MarshalPER(encoder)
}

// UnmarshalPER decodes the HoursUtcAndFractionEncoding using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (h *HoursUtcAndFractionEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		hours, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		h.Hours = hours
	}

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		fraction, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		h.Fraction = fraction
	}

	return nil
}

// UnmarshalAPER decodes the HoursUtcAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursUtcAndFractionEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return h.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the HoursUtcAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursUtcAndFractionEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return h.UnmarshalPER(decoder)
}
