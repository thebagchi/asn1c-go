package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// HoursAndDiffEncoding is the X.691 (02/2021) clause 32.3
// HOURS-AND-DIFF-ENCODING type, used to PER-encode a TIME-family value
// whose abstract values have the "Basic=Time Time=H Local-or-UTC=LD"
// property setting.
//
//	HOURS-AND-DIFF-ENCODING ::= SEQUENCE {
//	    local-hours     INTEGER (0..24),
//	    time-difference TIME-DIFFERENCE
//	}
type HoursAndDiffEncoding struct {
	LocalHours     int64           `per:"lb=0,ub=24"`
	TimeDifference *TimeDifference `per:""`
}

// MarshalPER encodes the HoursAndDiffEncoding using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (h *HoursAndDiffEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-hours INTEGER (0..24) — constrained lb=0, ub=24
	if err := encoder.EncodeInteger(h.LocalHours, CONSTRAINT_HOURS); err != nil {
		return nil, err
	}

	// time-difference TIME-DIFFERENCE
	if _, err := h.TimeDifference.MarshalPER(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the HoursAndDiffEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (h *HoursAndDiffEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return h.MarshalPER(encoder)
}

// MarshalUPER encodes the HoursAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (h *HoursAndDiffEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return h.MarshalPER(encoder)
}

// UnmarshalPER decodes the HoursAndDiffEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (h *HoursAndDiffEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-hours INTEGER (0..24) — constrained lb=0, ub=24
	localHours, err := decoder.DecodeInteger(CONSTRAINT_HOURS)
	if err != nil {
		return err
	}

	h.LocalHours = localHours

	// time-difference TIME-DIFFERENCE
	h.TimeDifference = &TimeDifference{}
	if err := h.TimeDifference.UnmarshalPER(decoder); err != nil {
		return err
	}

	return nil
}

// UnmarshalAPER decodes the HoursAndDiffEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (h *HoursAndDiffEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return h.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the HoursAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (h *HoursAndDiffEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return h.UnmarshalPER(decoder)
}
