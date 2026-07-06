package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// HoursEncoding is the X.691 (02/2021) clause 32.3 HOURS-ENCODING type,
// used to PER-encode a TIME-family value whose abstract values have the
// "Basic=Time Time=H Local-or-UTC=L" property setting.
//
//	HOURS-ENCODING ::= INTEGER (0..24) -- 5 bits
type HoursEncoding int64

// MarshalPER encodes the HoursEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (h *HoursEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// HOURS-ENCODING ::= INTEGER (0..24) — constrained lb=0, ub=24
	lb, ub := int64(0), int64(24)
	if err := encoder.EncodeInteger(int64(*h), &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the HoursEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return h.MarshalPER(encoder)
}

// MarshalUPER encodes the HoursEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return h.MarshalPER(encoder)
}

// UnmarshalPER decodes the HoursEncoding using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (h *HoursEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// HOURS-ENCODING ::= INTEGER (0..24) — constrained lb=0, ub=24
	lb, ub := int64(0), int64(24)
	value, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	*h = HoursEncoding(value)

	return nil
}

// UnmarshalAPER decodes the HoursEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return h.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the HoursEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return h.UnmarshalPER(decoder)
}
