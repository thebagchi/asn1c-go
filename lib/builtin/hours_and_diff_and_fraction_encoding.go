package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// HoursAndDiffAndFractionEncoding is the X.691 (02/2021) clause 32.3
// HOURS-AND-DIFF-AND-FRACTION-ENCODING type, used to PER-encode a
// TIME-family value whose abstract values have the "Basic=Time Time=HF3
// Local-or-UTC=LD" property setting.
//
//	HOURS-AND-DIFF-AND-FRACTION-ENCODING ::= SEQUENCE {
//	    local-hours     INTEGER (0..24), -- 5 bits
//	    fraction        INTEGER (0..999, ..., 1000..MAX), -- 11 bits for up to 3-digit accuracy
//	    time-difference TIME-DIFFERENCE
//	}
type HoursAndDiffAndFractionEncoding struct {
	LocalHours     int64           `per:"lb=0,ub=24"`
	Fraction       int64           `per:"lb=0,ub=999,ext"`
	TimeDifference *TimeDifference `per:""`
}

// MarshalPER encodes the HoursAndDiffAndFractionEncoding using Packed
// Encoding Rules onto encoder, so nested types can chain encoding onto a
// shared encoder. MarshalAPER/MarshalUPER create the encoder and call
// this.
func (h *HoursAndDiffAndFractionEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		if err := encoder.EncodeInteger(h.LocalHours, &lb, &ub, false); err != nil {
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

	// time-difference TIME-DIFFERENCE
	if _, err := h.TimeDifference.MarshalPER(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the HoursAndDiffAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursAndDiffAndFractionEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return h.MarshalPER(encoder)
}

// MarshalUPER encodes the HoursAndDiffAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursAndDiffAndFractionEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return h.MarshalPER(encoder)
}

// UnmarshalPER decodes the HoursAndDiffAndFractionEncoding using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (h *HoursAndDiffAndFractionEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		localHours, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		h.LocalHours = localHours
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

	// time-difference TIME-DIFFERENCE
	h.TimeDifference = &TimeDifference{}
	if err := h.TimeDifference.UnmarshalPER(decoder); err != nil {
		return err
	}

	return nil
}

// UnmarshalAPER decodes the HoursAndDiffAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (h *HoursAndDiffAndFractionEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return h.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the HoursAndDiffAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (h *HoursAndDiffAndFractionEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return h.UnmarshalPER(decoder)
}
