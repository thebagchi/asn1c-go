package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// TimeOfDayAndDiffEncoding_LocalTime is the anonymous inline SEQUENCE type
// of TIME-OF-DAY-AND-DIFF-ENCODING's "local-time" component.
//
//	SEQUENCE {
//	    hours   INTEGER (0..24),
//	    minutes INTEGER (0..59),
//	    seconds INTEGER (0..60)
//	}
type TimeOfDayAndDiffEncoding_LocalTime struct {
	Hours   int64 `per:"lb=0,ub=24"`
	Minutes int64 `per:"lb=0,ub=59"`
	Seconds int64 `per:"lb=0,ub=60"`
}

// MarshalPER encodes the TimeOfDayAndDiffEncoding_LocalTime using Packed
// Encoding Rules onto encoder, so nested types can chain encoding onto a
// shared encoder. MarshalAPER/MarshalUPER create the encoder and call
// this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (l *TimeOfDayAndDiffEncoding_LocalTime) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	if err := encoder.EncodeInteger(l.Hours, CONSTRAINT_HOURS); err != nil {
		return nil, err
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	if err := encoder.EncodeInteger(l.Minutes, CONSTRAINT_MINUTES); err != nil {
		return nil, err
	}

	// seconds INTEGER (0..60) — constrained lb=0, ub=60
	if err := encoder.EncodeInteger(l.Seconds, CONSTRAINT_SECONDS); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeOfDayAndDiffEncoding_LocalTime using Aligned Packed Encoding Rules
// (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (l *TimeOfDayAndDiffEncoding_LocalTime) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return l.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayAndDiffEncoding_LocalTime using Unaligned Packed Encoding Rules
// (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (l *TimeOfDayAndDiffEncoding_LocalTime) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return l.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayAndDiffEncoding_LocalTime using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (l *TimeOfDayAndDiffEncoding_LocalTime) UnmarshalPER(decoder *per.Decoder) error {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	hours, err := decoder.DecodeInteger(CONSTRAINT_HOURS)
	if err != nil {
		return err
	}

	l.Hours = hours

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	minutes, err := decoder.DecodeInteger(CONSTRAINT_MINUTES)
	if err != nil {
		return err
	}

	l.Minutes = minutes

	// seconds INTEGER (0..60) — constrained lb=0, ub=60
	seconds, err := decoder.DecodeInteger(CONSTRAINT_SECONDS)
	if err != nil {
		return err
	}

	l.Seconds = seconds

	return nil
}

// UnmarshalAPER decodes the TimeOfDayAndDiffEncoding_LocalTime using Aligned Packed Encoding Rules
// (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (l *TimeOfDayAndDiffEncoding_LocalTime) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return l.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayAndDiffEncoding_LocalTime using Unaligned Packed Encoding
// Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (l *TimeOfDayAndDiffEncoding_LocalTime) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return l.UnmarshalPER(decoder)
}

// TimeOfDayAndDiffEncoding is the X.691 (02/2021) clause 32.3
// TIME-OF-DAY-AND-DIFF-ENCODING type, used to PER-encode a TIME-family
// value whose abstract values have the "Basic=Time Time=HMS
// Local-or-UTC=LD" property setting.
//
//	TIME-OF-DAY-AND-DIFF-ENCODING ::= SEQUENCE {
//	    local-time SEQUENCE {
//	        hours   INTEGER (0..24),
//	        minutes INTEGER (0..59),
//	        seconds INTEGER (0..60)
//	    },
//	    time-difference TIME-DIFFERENCE
//	}
type TimeOfDayAndDiffEncoding struct {
	LocalTime      *TimeOfDayAndDiffEncoding_LocalTime `per:""`
	TimeDifference *TimeDifference                     `per:""`
}

// MarshalPER encodes the TimeOfDayAndDiffEncoding using Packed Encoding
// Rules onto encoder, so nested types can chain encoding onto a shared
// encoder. MarshalAPER/MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func (t *TimeOfDayAndDiffEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), seconds INTEGER
	// (0..60) }
	if _, err := t.LocalTime.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// time-difference TIME-DIFFERENCE
	if _, err := t.TimeDifference.MarshalPER(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeOfDayAndDiffEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (t *TimeOfDayAndDiffEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return t.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (t *TimeOfDayAndDiffEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return t.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayAndDiffEncoding using Packed Encoding
// Rules from decoder, so nested types can chain decoding off a shared
// decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func (t *TimeOfDayAndDiffEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), seconds INTEGER
	// (0..60) }
	t.LocalTime = &TimeOfDayAndDiffEncoding_LocalTime{}
	if err := t.LocalTime.UnmarshalPER(decoder); err != nil {
		return err
	}

	// time-difference TIME-DIFFERENCE
	t.TimeDifference = &TimeDifference{}
	if err := t.TimeDifference.UnmarshalPER(decoder); err != nil {
		return err
	}

	return nil
}

// UnmarshalAPER decodes the TimeOfDayAndDiffEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (t *TimeOfDayAndDiffEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return t.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (t *TimeOfDayAndDiffEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return t.UnmarshalPER(decoder)
}
