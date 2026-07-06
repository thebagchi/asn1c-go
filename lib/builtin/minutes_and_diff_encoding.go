package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// MinutesAndDiffEncoding_LocalTime is the anonymous inline SEQUENCE type of
// MINUTES-AND-DIFF-ENCODING's "local-time" component.
//
//	SEQUENCE {
//	    hours   INTEGER (0..24),
//	    minutes INTEGER (0..59)
//	}
type MinutesAndDiffEncoding_LocalTime struct {
	Hours   int64 `per:"lb=0,ub=24"`
	Minutes int64 `per:"lb=0,ub=59"`
}

// MarshalPER encodes the MinutesAndDiffEncoding_LocalTime using Packed
// Encoding Rules onto encoder, so nested types can chain encoding onto a
// shared encoder. MarshalAPER/MarshalUPER create the encoder and call this.
func (l *MinutesAndDiffEncoding_LocalTime) MarshalPER(encoder *per.Encoder) ([]byte, error) {
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

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the MinutesAndDiffEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *MinutesAndDiffEncoding_LocalTime) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return l.MarshalPER(encoder)
}

// MarshalUPER encodes the MinutesAndDiffEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *MinutesAndDiffEncoding_LocalTime) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return l.MarshalPER(encoder)
}

// UnmarshalPER decodes the MinutesAndDiffEncoding_LocalTime using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (l *MinutesAndDiffEncoding_LocalTime) UnmarshalPER(decoder *per.Decoder) error {
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

	return nil
}

// UnmarshalAPER decodes the MinutesAndDiffEncoding_LocalTime using Aligned Packed Encoding Rules (APER).
func (l *MinutesAndDiffEncoding_LocalTime) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return l.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the MinutesAndDiffEncoding_LocalTime using Unaligned Packed Encoding Rules (UPER).
func (l *MinutesAndDiffEncoding_LocalTime) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return l.UnmarshalPER(decoder)
}

// MinutesAndDiffEncoding is the X.691 (02/2021) clause 32.3
// MINUTES-AND-DIFF-ENCODING type, used to PER-encode a TIME-family value
// whose abstract values have the "Basic=Time Time=HM Local-or-UTC=LD"
// property setting.
//
//	MINUTES-AND-DIFF-ENCODING ::= SEQUENCE {
//	    local-time SEQUENCE {
//	        hours   INTEGER (0..24),
//	        minutes INTEGER (0..59)
//	    },
//	    time-difference TIME-DIFFERENCE
//	}
type MinutesAndDiffEncoding struct {
	LocalTime      *MinutesAndDiffEncoding_LocalTime `per:""`
	TimeDifference *TimeDifference                   `per:""`
}

// MarshalPER encodes the MinutesAndDiffEncoding using Packed Encoding
// Rules onto encoder, so nested types can chain encoding onto a shared
// encoder. MarshalAPER/MarshalUPER create the encoder and call this.
func (m *MinutesAndDiffEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59) }
	if _, err := m.LocalTime.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// time-difference TIME-DIFFERENCE
	if _, err := m.TimeDifference.MarshalPER(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the MinutesAndDiffEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesAndDiffEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return m.MarshalPER(encoder)
}

// MarshalUPER encodes the MinutesAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesAndDiffEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return m.MarshalPER(encoder)
}

// UnmarshalPER decodes the MinutesAndDiffEncoding using Packed Encoding
// Rules from decoder, so nested types can chain decoding off a shared
// decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (m *MinutesAndDiffEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// local-time SEQUENCE { hours INTEGER (0..24), minutes INTEGER (0..59) }
	m.LocalTime = &MinutesAndDiffEncoding_LocalTime{}
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

// UnmarshalAPER decodes the MinutesAndDiffEncoding using Aligned Packed Encoding Rules (APER).
func (m *MinutesAndDiffEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return m.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the MinutesAndDiffEncoding using Unaligned Packed Encoding Rules (UPER).
func (m *MinutesAndDiffEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return m.UnmarshalPER(decoder)
}
