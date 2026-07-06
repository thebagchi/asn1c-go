package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// TimeDifferenceSign identifies the ENUMERATED "sign" component of
// TIME-DIFFERENCE (X.680 clause 20 ENUMERATED, PER-encoded per X.691
// clause 14 as a constrained whole number over the enumeration index).
type TimeDifferenceSign uint64

const (
	TIME_DIFFERENCE_SIGN_POSITIVE TimeDifferenceSign = iota
	TIME_DIFFERENCE_SIGN_NEGATIVE
)

// NUM_ENTRIES_TIME_DIFFERENCE_SIGN is the number of root (non-extensible)
// enumerators in TimeDifferenceSign, used as the "count" argument to
// EncodeEnumerated/DecodeEnumerated.
const NUM_ENTRIES_TIME_DIFFERENCE_SIGN = 2

// MarshalPER encodes the TimeDifferenceSign using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (s *TimeDifferenceSign) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	if err := encoder.EncodeEnumerated(uint64(*s), NUM_ENTRIES_TIME_DIFFERENCE_SIGN, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeDifferenceSign using Aligned Packed Encoding Rules (APER).
func (s *TimeDifferenceSign) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return s.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeDifferenceSign using Unaligned Packed Encoding Rules (UPER).
func (s *TimeDifferenceSign) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return s.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeDifferenceSign using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (s *TimeDifferenceSign) UnmarshalPER(decoder *per.Decoder) error {
	value, err := decoder.DecodeEnumerated(NUM_ENTRIES_TIME_DIFFERENCE_SIGN, false)
	if err != nil {
		return err
	}
	*s = TimeDifferenceSign(value)

	return nil
}

// UnmarshalAPER decodes the TimeDifferenceSign using Aligned Packed Encoding Rules (APER).
func (s *TimeDifferenceSign) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return s.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeDifferenceSign using Unaligned Packed Encoding Rules (UPER).
func (s *TimeDifferenceSign) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return s.UnmarshalPER(decoder)
}

// TimeDifference is the X.691 (02/2021) clause 32.3 TIME-DIFFERENCE type, a
// shared helper SEQUENCE used by every "-AND-DIFF" TIME encoding variant
// (HOURS-AND-DIFF-ENCODING, MINUTES-AND-DIFF-ENCODING,
// TIME-OF-DAY-AND-DIFF-ENCODING).
//
//	TIME-DIFFERENCE ::= SEQUENCE {
//	    sign    ENUMERATED { positive, negative },
//	    hours   INTEGER (0..15),
//	    minutes INTEGER (1..59) OPTIONAL -- omitted if zero
//	}
//
// Minutes is nil when the component is omitted (per the comment, this is
// always the case when the abstract minutes value is zero, since the
// constraint 1..59 excludes zero from ever being an encodable present
// value).
type TimeDifference struct {
	Sign    TimeDifferenceSign
	Hours   int64
	Minutes *int64
}

// MarshalPER encodes the TimeDifference using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (t *TimeDifference) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// Root preamble (X.691 19.2-19.3): one presence bit per OPTIONAL/DEFAULT
	// component, in declaration order, before any component value.
	if err := encoder.EncodeBoolean(t.Minutes != nil); err != nil {
		return nil, err
	}

	// sign ENUMERATED { positive, negative }
	if _, err := t.Sign.MarshalPER(encoder); err != nil {
		return nil, err
	}

	// hours INTEGER (0..15) — constrained lb=0, ub=15
	{
		lb, ub := int64(0), int64(15)
		if err := encoder.EncodeInteger(t.Hours, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	// minutes INTEGER (1..59) OPTIONAL — constrained lb=1, ub=59
	if t.Minutes != nil {
		lb, ub := int64(1), int64(59)
		if err := encoder.EncodeInteger(*t.Minutes, &lb, &ub, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the TimeDifference using Aligned Packed Encoding Rules (APER).
func (t *TimeDifference) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return t.MarshalPER(encoder)
}

// MarshalUPER encodes the TimeDifference using Unaligned Packed Encoding Rules (UPER).
func (t *TimeDifference) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return t.MarshalPER(encoder)
}

// UnmarshalPER decodes the TimeDifference using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (t *TimeDifference) UnmarshalPER(decoder *per.Decoder) error {
	// Root preamble (X.691 19.2-19.3): one presence bit per OPTIONAL/DEFAULT
	// component, in declaration order, before any component value.
	minutesPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}

	// sign ENUMERATED { positive, negative }
	if err := t.Sign.UnmarshalPER(decoder); err != nil {
		return err
	}

	// hours INTEGER (0..15) — constrained lb=0, ub=15
	{
		lb, ub := int64(0), int64(15)
		hours, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		t.Hours = hours
	}

	// minutes INTEGER (1..59) OPTIONAL — constrained lb=1, ub=59
	if minutesPresent {
		lb, ub := int64(1), int64(59)
		minutes, err := decoder.DecodeInteger(&lb, &ub, false)
		if err != nil {
			return err
		}
		t.Minutes = &minutes
	} else {
		t.Minutes = nil
	}

	return nil
}

// UnmarshalAPER decodes the TimeDifference using Aligned Packed Encoding Rules (APER).
func (t *TimeDifference) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return t.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the TimeDifference using Unaligned Packed Encoding Rules (UPER).
func (t *TimeDifference) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return t.UnmarshalPER(decoder)
}
