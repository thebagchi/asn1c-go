package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// HoursUtcEncoding is the X.691 (02/2021) clause 32.3 HOURS-UTC-ENCODING
// type, used to PER-encode a TIME-family value whose abstract values have
// the "Basic=Time Time=H Local-or-UTC=Z" property setting.
//
//	HOURS-UTC-ENCODING ::= INTEGER (0..24) -- 5 bits
type HoursUtcEncoding int64

// MarshalPER encodes the HoursUtcEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (h *HoursUtcEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// HOURS-UTC-ENCODING ::= INTEGER (0..24) — constrained lb=0, ub=24
	lb, ub := int64(0), int64(24)
	if err := encoder.EncodeInteger(int64(*h), &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the HoursUtcEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursUtcEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return h.MarshalPER(encoder)
}

// MarshalUPER encodes the HoursUtcEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursUtcEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return h.MarshalPER(encoder)
}

// UnmarshalPER decodes the HoursUtcEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (h *HoursUtcEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// HOURS-UTC-ENCODING ::= INTEGER (0..24) — constrained lb=0, ub=24
	lb, ub := int64(0), int64(24)
	value, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	*h = HoursUtcEncoding(value)

	return nil
}

// UnmarshalAPER decodes the HoursUtcEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursUtcEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return h.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the HoursUtcEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursUtcEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return h.UnmarshalPER(decoder)
}
