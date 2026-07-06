package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// MinutesAndDiffAndFractionEncoding_LocalTime is the anonymous inline
// SEQUENCE type of MINUTES-AND-DIFF-AND-FRACTION-ENCODING's "local-time"
// component.
//
//	SEQUENCE {
//	    hours    INTEGER (0..24),
//	    minutes  INTEGER (0..59),
//	    fraction INTEGER (0..999, ..., 1000..MAX)
//	}
type MinutesAndDiffAndFractionEncoding_LocalTime struct {
	Hours    int64 `per:"lb=0,ub=24"`
	Minutes  int64 `per:"lb=0,ub=59"`
	Fraction int64 `per:"lb=0,ub=999,ext"`
}

// MarshalPER encodes the MinutesAndDiffAndFractionEncoding_LocalTime using
// Packed Encoding Rules onto encoder, so nested types can chain encoding
// onto a shared encoder. MarshalAPER/MarshalUPER create the encoder and
// call this.
func (l *MinutesAndDiffAndFractionEncoding_LocalTime) MarshalPER(encoder *per.Encoder) ([]byte, error) {
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

	// fraction INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		if err := encoder.EncodeInteger(l.Fraction, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the MinutesAndDiffAndFractionEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *MinutesAndDiffAndFractionEncoding_LocalTime) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return l.MarshalPER(encoder)
}

// MarshalUPER encodes the MinutesAndDiffAndFractionEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *MinutesAndDiffAndFractionEncoding_LocalTime) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return l.MarshalPER(encoder)
}

// UnmarshalPER decodes the MinutesAndDiffAndFractionEncoding_LocalTime
// using Packed Encoding Rules from decoder, so nested types can chain
// decoding off a shared decoder. UnmarshalAPER/UnmarshalUPER create the
// decoder and call this.
func (l *MinutesAndDiffAndFractionEncoding_LocalTime) UnmarshalPER(decoder *per.Decoder) error {
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

// UnmarshalAPER decodes the MinutesAndDiffAndFractionEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *MinutesAndDiffAndFractionEncoding_LocalTime) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return l.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the MinutesAndDiffAndFractionEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *MinutesAndDiffAndFractionEncoding_LocalTime) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return l.UnmarshalPER(decoder)
}

// MinutesAndDiffAndFractionEncoding is the X.691 (02/2021) clause 32.3
// MINUTES-AND-DIFF-AND-FRACTION-ENCODING type, used to PER-encode a
// TIME-family value whose abstract values have the "Basic=Time Time=HMF3
// Local-or-UTC=LD" property setting.
//
//	MINUTES-AND-DIFF-AND-FRACTION-ENCODING ::= SEQUENCE {
//	    local-time SEQUENCE {
//	        hours    INTEGER (0..24),
//	        minutes  INTEGER (0..59),
//	        fraction INTEGER (0..999, ..., 1000..MAX)
//	    },
//	    time-difference TIME-DIFFERENCE
//	}
type MinutesAndDiffAndFractionEncoding struct {
	LocalTime      *MinutesAndDiffAndFractionEncoding_LocalTime `per:""`
	TimeDifference *TimeDifference                              `per:""`
}

// MarshalPER encodes the MinutesAndDiffAndFractionEncoding using Packed
// Encoding Rules onto encoder, so nested types can chain encoding onto a
// shared encoder. MarshalAPER/MarshalUPER create the encoder and call
// this.
func (m *MinutesAndDiffAndFractionEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), fraction INTEGER (0..999, ..., 1000..MAX) }
	if _, err := m.LocalTime.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// time-difference TIME-DIFFERENCE
	if _, err := m.TimeDifference.MarshalPER(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the MinutesAndDiffAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesAndDiffAndFractionEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return m.MarshalPER(encoder)
}

// MarshalUPER encodes the MinutesAndDiffAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesAndDiffAndFractionEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return m.MarshalPER(encoder)
}

// UnmarshalPER decodes the MinutesAndDiffAndFractionEncoding using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (m *MinutesAndDiffAndFractionEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59), fraction INTEGER (0..999, ..., 1000..MAX) }
	m.LocalTime = &MinutesAndDiffAndFractionEncoding_LocalTime{}
	if err := m.LocalTime.UnmarshalPER(decoder); err != nil {
		return err
	}

	// time-difference TIME-DIFFERENCE
	m.TimeDifference = &TimeDifference{}
	if err := m.TimeDifference.UnmarshalPER(decoder); err != nil {
		return err
	}

	return nil
}

// UnmarshalAPER decodes the MinutesAndDiffAndFractionEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesAndDiffAndFractionEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return m.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the MinutesAndDiffAndFractionEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesAndDiffAndFractionEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return m.UnmarshalPER(decoder)
}
