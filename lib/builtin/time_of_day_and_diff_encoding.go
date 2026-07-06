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
func (l *TimeOfDayAndDiffEncoding_LocalTime) MarshalPER(encoder *per.Encoder) ([]byte, error) {
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

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeOfDayAndDiffEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *TimeOfDayAndDiffEncoding_LocalTime) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return l.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayAndDiffEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *TimeOfDayAndDiffEncoding_LocalTime) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return l.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayAndDiffEncoding_LocalTime using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (l *TimeOfDayAndDiffEncoding_LocalTime) UnmarshalPER(decoder *per.Decoder) error {
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

	return nil
}

// UnmarshalAPER decodes the TimeOfDayAndDiffEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *TimeOfDayAndDiffEncoding_LocalTime) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return l.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayAndDiffEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *TimeOfDayAndDiffEncoding_LocalTime) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
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
func (t *TimeOfDayAndDiffEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), seconds INTEGER (0..60) }
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
func (t *TimeOfDayAndDiffEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return t.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeOfDayAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
func (t *TimeOfDayAndDiffEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return t.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeOfDayAndDiffEncoding using Packed Encoding
// Rules from decoder, so nested types can chain decoding off a shared
// decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (t *TimeOfDayAndDiffEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), seconds INTEGER (0..60) }
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
func (t *TimeOfDayAndDiffEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return t.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeOfDayAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
func (t *TimeOfDayAndDiffEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return t.UnmarshalPER(decoder)
}
