package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// DurationIntervalEncoding_FractionalPart is the anonymous inline SEQUENCE
// type of DURATION-INTERVAL-ENCODING's "fractional-part" component.
//
//	SEQUENCE {
//	    number-of-digits INTEGER (1..3, ..., 4..MAX),  -- 3 bits for up to 3-digit accuracy
//	    fractional-value INTEGER (0..999, ..., 1000..MAX) -- 11 bits for up to 3-digit accuracy
//	}
type DurationIntervalEncoding_FractionalPart struct {
	NumberOfDigits  int64 `per:"lb=1,ub=3,ext"`
	FractionalValue int64 `per:"lb=0,ub=999,ext"`
}

// MarshalPER encodes the DurationIntervalEncoding_FractionalPart using
// Packed Encoding Rules onto encoder, so nested types can chain encoding
// onto a shared encoder. MarshalAPER/MarshalUPER create the encoder and
// call this.
func (f *DurationIntervalEncoding_FractionalPart) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// number-of-digits INTEGER (1..3, ..., 4..MAX) — constrained lb=1, ub=3, extensible
	{
		lb, ub := int64(1), int64(3)
		if err := encoder.EncodeInteger(f.NumberOfDigits, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// fractional-value INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		if err := encoder.EncodeInteger(f.FractionalValue, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationIntervalEncoding_FractionalPart using Aligned Packed Encoding Rules (APER).
func (f *DurationIntervalEncoding_FractionalPart) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return f.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationIntervalEncoding_FractionalPart using Unaligned Packed Encoding Rules (UPER).
func (f *DurationIntervalEncoding_FractionalPart) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return f.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationIntervalEncoding_FractionalPart using
// Packed Encoding Rules from decoder, so nested types can chain decoding
// off a shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and
// call this.
func (f *DurationIntervalEncoding_FractionalPart) UnmarshalPER(decoder *per.Decoder) error {
	// number-of-digits INTEGER (1..3, ..., 4..MAX) — constrained lb=1, ub=3, extensible
	{
		lb, ub := int64(1), int64(3)
		numberOfDigits, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		f.NumberOfDigits = numberOfDigits
	}

	// fractional-value INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	{
		lb, ub := int64(0), int64(999)
		fractionalValue, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		f.FractionalValue = fractionalValue
	}

	return nil
}

// UnmarshalAPER decodes the DurationIntervalEncoding_FractionalPart using Aligned Packed Encoding Rules (APER).
func (f *DurationIntervalEncoding_FractionalPart) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return f.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationIntervalEncoding_FractionalPart using Unaligned Packed Encoding Rules (UPER).
func (f *DurationIntervalEncoding_FractionalPart) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return f.UnmarshalPER(decoder)
}

// DurationIntervalEncoding is the X.691 (02/2021) clause 32.6
// DURATION-INTERVAL-ENCODING type, used to PER-encode a value with the
// "Basic=Interval Interval-type=D" property setting (duration). The weeks
// component is present iff years/months/days/hours/minutes/seconds are
// all absent; a zero-valued time element is present only if it is the
// least-significant one, or has a fractional part, keeping the encoding
// canonical.
//
//	DURATION-INTERVAL-ENCODING ::= SEQUENCE { -- 8 bits for optionality
//	    years   INTEGER (0..31, ..., 32..MAX) OPTIONAL, -- 5 bits for up to 31 years
//	    months  INTEGER (0..15, ..., 16..MAX) OPTIONAL, -- 4 bits for up to 15 months
//	    weeks   INTEGER (0..63, ..., 64..MAX) OPTIONAL, -- 6 bits for up to 63 weeks
//	    days    INTEGER (0..31, ..., 32..MAX) OPTIONAL, -- 5 bits for up to 31 days
//	    hours   INTEGER (0..31, ..., 32..MAX) OPTIONAL, -- 5 bits for up to 31 hours
//	    minutes INTEGER (0..63, ..., 64..MAX) OPTIONAL, -- 6 bits for up to 63 minutes
//	    seconds INTEGER (0..63, ..., 64..MAX) OPTIONAL, -- 6 bits for up to 63 seconds
//	    fractional-part SEQUENCE {
//	        number-of-digits INTEGER (1..3, ..., 4..MAX),  -- 3 bits for up to 3-digit accuracy
//	        fractional-value INTEGER (0..999, ..., 1000..MAX) -- 11 bits for up to 3-digit accuracy
//	    } OPTIONAL
//	}
//
// Each field is nil when the corresponding OPTIONAL component is absent.
type DurationIntervalEncoding struct {
	Years          *int64                                   `per:"lb=0,ub=31,ext,opt"`
	Months         *int64                                   `per:"lb=0,ub=15,ext,opt"`
	Weeks          *int64                                   `per:"lb=0,ub=63,ext,opt"`
	Days           *int64                                   `per:"lb=0,ub=31,ext,opt"`
	Hours          *int64                                   `per:"lb=0,ub=31,ext,opt"`
	Minutes        *int64                                   `per:"lb=0,ub=63,ext,opt"`
	Seconds        *int64                                   `per:"lb=0,ub=63,ext,opt"`
	FractionalPart *DurationIntervalEncoding_FractionalPart `per:"opt"`
}

// MarshalPER encodes the DurationIntervalEncoding using Packed Encoding
// Rules onto encoder, so nested types can chain encoding onto a shared
// encoder. MarshalAPER/MarshalUPER create the encoder and call this.
func (d *DurationIntervalEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// Root preamble (X.691 19.2-19.3): one presence bit per OPTIONAL
	// component, in declaration order, before any component value.
	if err := encoder.EncodeBoolean(d.Years != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.Months != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.Weeks != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.Days != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.Hours != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.Minutes != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.Seconds != nil); err != nil {
		return nil, err
	}
	if err := encoder.EncodeBoolean(d.FractionalPart != nil); err != nil {
		return nil, err
	}

	// years INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if d.Years != nil {
		lb, ub := int64(0), int64(31)
		if err := encoder.EncodeInteger(*d.Years, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// months INTEGER (0..15, ..., 16..MAX) OPTIONAL — constrained lb=0, ub=15, extensible
	if d.Months != nil {
		lb, ub := int64(0), int64(15)
		if err := encoder.EncodeInteger(*d.Months, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// weeks INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if d.Weeks != nil {
		lb, ub := int64(0), int64(63)
		if err := encoder.EncodeInteger(*d.Weeks, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// days INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if d.Days != nil {
		lb, ub := int64(0), int64(31)
		if err := encoder.EncodeInteger(*d.Days, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// hours INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if d.Hours != nil {
		lb, ub := int64(0), int64(31)
		if err := encoder.EncodeInteger(*d.Hours, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// minutes INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if d.Minutes != nil {
		lb, ub := int64(0), int64(63)
		if err := encoder.EncodeInteger(*d.Minutes, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// seconds INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if d.Seconds != nil {
		lb, ub := int64(0), int64(63)
		if err := encoder.EncodeInteger(*d.Seconds, &lb, &ub, true); err != nil {
			return nil, err
		}
	}

	// fractional-part SEQUENCE { ... } OPTIONAL
	if d.FractionalPart != nil {
		if _, err := d.FractionalPart.MarshalPER(encoder); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationIntervalEncoding using Aligned Packed Encoding Rules (APER).
func (d *DurationIntervalEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return d.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationIntervalEncoding using Unaligned Packed Encoding Rules (UPER).
func (d *DurationIntervalEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return d.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationIntervalEncoding using Packed Encoding
// Rules from decoder, so nested types can chain decoding off a shared
// decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (d *DurationIntervalEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// Root preamble (X.691 19.2-19.3): one presence bit per OPTIONAL
	// component, in declaration order, before any component value.
	yearsPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	monthsPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	weeksPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	daysPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	hoursPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	minutesPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	secondsPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}
	fractionalPartPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return err
	}

	// years INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if yearsPresent {
		lb, ub := int64(0), int64(31)
		years, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Years = &years
	} else {
		d.Years = nil
	}

	// months INTEGER (0..15, ..., 16..MAX) OPTIONAL — constrained lb=0, ub=15, extensible
	if monthsPresent {
		lb, ub := int64(0), int64(15)
		months, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Months = &months
	} else {
		d.Months = nil
	}

	// weeks INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if weeksPresent {
		lb, ub := int64(0), int64(63)
		weeks, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Weeks = &weeks
	} else {
		d.Weeks = nil
	}

	// days INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if daysPresent {
		lb, ub := int64(0), int64(31)
		days, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Days = &days
	} else {
		d.Days = nil
	}

	// hours INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if hoursPresent {
		lb, ub := int64(0), int64(31)
		hours, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Hours = &hours
	} else {
		d.Hours = nil
	}

	// minutes INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if minutesPresent {
		lb, ub := int64(0), int64(63)
		minutes, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Minutes = &minutes
	} else {
		d.Minutes = nil
	}

	// seconds INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if secondsPresent {
		lb, ub := int64(0), int64(63)
		seconds, err := decoder.DecodeInteger(&lb, &ub, true)
		if err != nil {
			return err
		}
		d.Seconds = &seconds
	} else {
		d.Seconds = nil
	}

	// fractional-part SEQUENCE { ... } OPTIONAL
	if fractionalPartPresent {
		d.FractionalPart = &DurationIntervalEncoding_FractionalPart{}
		if err := d.FractionalPart.UnmarshalPER(decoder); err != nil {
			return err
		}
	} else {
		d.FractionalPart = nil
	}

	return nil
}

// UnmarshalAPER decodes the DurationIntervalEncoding using Aligned Packed Encoding Rules (APER).
func (d *DurationIntervalEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return d.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationIntervalEncoding using Unaligned Packed Encoding Rules (UPER).
func (d *DurationIntervalEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return d.UnmarshalPER(decoder)
}
