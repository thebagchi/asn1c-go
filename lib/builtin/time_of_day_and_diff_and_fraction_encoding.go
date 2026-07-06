package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// TimeOfDayAndDiffAndFractionEncoding_LocalTime is the anonymous inline
// SEQUENCE type of TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING's
// "local-time" component.
//
//	SEQUENCE {
//	    hours    INTEGER (0..24),
//	    minutes  INTEGER (0..59),
//	    seconds  INTEGER (0..60),
//	    fraction INTEGER (0..999, ..., 1000..MAX)
//	}
type TimeOfDayAndDiffAndFractionEncoding_LocalTime struct {
	Hours    int64 `per:"lb=0,ub=24"`
	Minutes  int64 `per:"lb=0,ub=59"`
	Seconds  int64 `per:"lb=0,ub=60"`
	Fraction int64 `per:"lb=0,ub=999,ext"`
}

// MarshalPER encodes the TimeOfDayAndDiffAndFractionEncoding_LocalTime
// using Packed Encoding Rules onto encoder, so nested types can chain
// encoding onto a shared encoder. MarshalAPER/MarshalUPER create the
// encoder and call this.
func (l *TimeOfDayAndDiffAndFractionEncoding_LocalTime) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		if err := encoder.EncodeInteger(l.Hours, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	{
		lb, ub := int64(0), int64(59)
		if err := encoder.EncodeInteger(l.Minutes, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// seconds INTEGER (0..60) — constrained lb=0, ub=60
	{
		lb, ub := int64(0), int64(60)
		if err := encoder.EncodeInteger(l.Seconds, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		if err := encoder.EncodeInteger(l.Fraction, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeOfDayAndDiffAndFractionEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *TimeOfDayAndDiffAndFractionEncoding_LocalTime) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return l.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayAndDiffAndFractionEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *TimeOfDayAndDiffAndFractionEncoding_LocalTime) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return l.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayAndDiffAndFractionEncoding_LocalTime
// using Packed Encoding Rules from decoder, so nested types can chain
// decoding off a shared decoder. UnmarshalAPER/UnmarshalUPER create the
// decoder and call this.
func (l *TimeOfDayAndDiffAndFractionEncoding_LocalTime) UnmarshalPER(decoder *per.Decoder) error {
	// hours INTEGER (0..24) — constrained lb=0, ub=24
	{
		lb, ub := int64(0), int64(24)
		hours, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		l.Hours = hours
	}

	// minutes INTEGER (0..59) — constrained lb=0, ub=59
	{
		lb, ub := int64(0), int64(59)
		minutes, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		l.Minutes = minutes
	}

	// seconds INTEGER (0..60) — constrained lb=0, ub=60
	{
		lb, ub := int64(0), int64(60)
		seconds, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		l.Seconds = seconds
	}

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		fraction, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		l.Fraction = fraction
	}

	return nil
}

// UnmarshalAPER decodes the TimeOfDayAndDiffAndFractionEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *TimeOfDayAndDiffAndFractionEncoding_LocalTime) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return l.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayAndDiffAndFractionEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *TimeOfDayAndDiffAndFractionEncoding_LocalTime) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return l.UnmarshalPER(decoder)
}

// TimeOfDayAndDiffAndFractionEncoding is the X.691 (02/2021) clause 32.3
// TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING type, used to PER-encode a
// TIME-family value whose abstract values have the "Basic=Time
// Time=HMSF3 Local-or-UTC=LD" property setting.
//
//	TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING ::= SEQUENCE {
//	    local-time SEQUENCE {
//	        hours    INTEGER (0..24),
//	        minutes  INTEGER (0..59),
//	        seconds  INTEGER (0..60),
//	        fraction INTEGER (0..999, ..., 1000..MAX)
//	    },
//	    time-difference TIME-DIFFERENCE
//	}
type TimeOfDayAndDiffAndFractionEncoding struct {
	LocalTime      *TimeOfDayAndDiffAndFractionEncoding_LocalTime `per:""`
	TimeDifference *TimeDifference                                `per:""`
}

// MarshalPER encodes the TimeOfDayAndDiffAndFractionEncoding using Packed
// Encoding Rules onto encoder, so nested types can chain encoding onto a
// shared encoder. MarshalAPER/MarshalUPER create the encoder and call
// this.
func (t *TimeOfDayAndDiffAndFractionEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), seconds INTEGER (0..60), fraction INTEGER (0..999, ..., 1000..MAX) }
	if _, err := t.LocalTime.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// time-difference TIME-DIFFERENCE
	if _, err := t.TimeDifference.MarshalPER(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeOfDayAndDiffAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (t *TimeOfDayAndDiffAndFractionEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return t.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayAndDiffAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (t *TimeOfDayAndDiffAndFractionEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return t.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayAndDiffAndFractionEncoding using
// Packed Encoding Rules from decoder, so nested types can chain decoding
// off a shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and
// call this.
func (t *TimeOfDayAndDiffAndFractionEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), seconds INTEGER (0..60), fraction INTEGER (0..999, ..., 1000..MAX) }
	t.LocalTime = &TimeOfDayAndDiffAndFractionEncoding_LocalTime{}
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

// UnmarshalAPER decodes the TimeOfDayAndDiffAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (t *TimeOfDayAndDiffAndFractionEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return t.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayAndDiffAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (t *TimeOfDayAndDiffAndFractionEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return t.UnmarshalPER(decoder)
}
