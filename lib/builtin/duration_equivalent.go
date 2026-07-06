package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// DurationEquivalent_FractionalPart is the anonymous inline SEQUENCE type
// of DURATION-EQUIVALENT's "fractional-part" component.
//
//	SEQUENCE {
//	    number-of-digits  INTEGER (1..MAX),
//	    fractional-value  INTEGER (0..MAX)
//	}
type DurationEquivalent_FractionalPart struct {
	NumberOfDigits  int64 `per:"lb=1"`
	FractionalValue int64 `per:"lb=0"`
}

// MarshalPER encodes the DurationEquivalent_FractionalPart using Packed
// Encoding Rules onto encoder, so nested types can chain encoding onto a
// shared encoder. MarshalAPER/MarshalUPER create the encoder and call
// this.
func (f *DurationEquivalent_FractionalPart) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// number-of-digits INTEGER (1..MAX) — semi-constrained lb=1
	{
		lb := int64(1)
		if err := encoder.EncodeInteger(f.NumberOfDigits, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// fractional-value INTEGER (0..MAX) — semi-constrained lb=0
	{
		lb := int64(0)
		if err := encoder.EncodeInteger(f.FractionalValue, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationEquivalent_FractionalPart using Aligned Packed Encoding Rules (APER).
func (f *DurationEquivalent_FractionalPart) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return f.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationEquivalent_FractionalPart using Unaligned Packed Encoding Rules (UPER).
func (f *DurationEquivalent_FractionalPart) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return f.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationEquivalent_FractionalPart using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
func (f *DurationEquivalent_FractionalPart) UnmarshalPER(decoder *per.Decoder) error {
	// number-of-digits INTEGER (1..MAX) — semi-constrained lb=1
	{
		lb := int64(1)
		numberOfDigits, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		f.NumberOfDigits = numberOfDigits
	}

	// fractional-value INTEGER (0..MAX) — semi-constrained lb=0
	{
		lb := int64(0)
		fractionalValue, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		f.FractionalValue = fractionalValue
	}

	return nil
}

// UnmarshalAPER decodes the DurationEquivalent_FractionalPart using Aligned Packed Encoding Rules (APER).
func (f *DurationEquivalent_FractionalPart) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return f.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationEquivalent_FractionalPart using Unaligned Packed Encoding Rules (UPER).
func (f *DurationEquivalent_FractionalPart) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return f.UnmarshalPER(decoder)
}

// DurationEquivalent is the X.680 clause 38.4.4.2 DURATION-EQUIVALENT
// type, the equivalent SEQUENCE type used to place inner subtyping
// constraints on a duration subtype of TIME (forbidding/requiring
// particular time components, or range-constraining their values). The
// years component corresponds to the years time component of the duration
// abstract value, and so on.
//
//	DURATION-EQUIVALENT ::= SEQUENCE {
//	    years           INTEGER (0..MAX) OPTIONAL,
//	    months          INTEGER (0..MAX) OPTIONAL,
//	    weeks           INTEGER (0..MAX) OPTIONAL,
//	    days            INTEGER (0..MAX) OPTIONAL,
//	    hours           INTEGER (0..MAX) OPTIONAL,
//	    minutes         INTEGER (0..MAX) OPTIONAL,
//	    seconds         INTEGER (0..MAX) OPTIONAL,
//	    fractional-part SEQUENCE {
//	        number-of-digits  INTEGER (1..MAX),
//	        fractional-value  INTEGER (0..MAX)
//	    } OPTIONAL
//	}
//
// Each field is nil when the corresponding OPTIONAL component is absent.
// Unlike DURATION-INTERVAL-ENCODING (X.691 clause 32.6), these components
// are plain semi-constrained integers with no extension marker: this type
// isn't itself PER-encoded on the wire, only used to express constraints,
// but it gets the same MarshalPER/UnmarshalPER treatment as every other
// SEQUENCE here for consistency.
type DurationEquivalent struct {
	Years          *int64                             `per:"lb=0,opt"`
	Months         *int64                             `per:"lb=0,opt"`
	Weeks          *int64                             `per:"lb=0,opt"`
	Days           *int64                             `per:"lb=0,opt"`
	Hours          *int64                             `per:"lb=0,opt"`
	Minutes        *int64                             `per:"lb=0,opt"`
	Seconds        *int64                             `per:"lb=0,opt"`
	FractionalPart *DurationEquivalent_FractionalPart `per:"opt"`
}

// MarshalPER encodes the DurationEquivalent using Packed Encoding Rules
// onto encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (d *DurationEquivalent) MarshalPER(encoder *per.Encoder) ([]byte, error) {
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

	// years INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Years != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Years, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// months INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Months != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Months, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// weeks INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Weeks != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Weeks, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// days INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Days != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Days, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// hours INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Hours != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Hours, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// minutes INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Minutes != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Minutes, &lb, nil, false); err != nil {
			return nil, err
		}
	}

	// seconds INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Seconds != nil {
		lb := int64(0)
		if err := encoder.EncodeInteger(*d.Seconds, &lb, nil, false); err != nil {
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

// MarshalAPER encodes the DurationEquivalent using Aligned Packed Encoding Rules (APER).
func (d *DurationEquivalent) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return d.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationEquivalent using Unaligned Packed Encoding Rules (UPER).
func (d *DurationEquivalent) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return d.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationEquivalent using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (d *DurationEquivalent) UnmarshalPER(decoder *per.Decoder) error {
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

	// years INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if yearsPresent {
		lb := int64(0)
		years, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Years = &years
	} else {
		d.Years = nil
	}

	// months INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if monthsPresent {
		lb := int64(0)
		months, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Months = &months
	} else {
		d.Months = nil
	}

	// weeks INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if weeksPresent {
		lb := int64(0)
		weeks, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Weeks = &weeks
	} else {
		d.Weeks = nil
	}

	// days INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if daysPresent {
		lb := int64(0)
		days, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Days = &days
	} else {
		d.Days = nil
	}

	// hours INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if hoursPresent {
		lb := int64(0)
		hours, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Hours = &hours
	} else {
		d.Hours = nil
	}

	// minutes INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if minutesPresent {
		lb := int64(0)
		minutes, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Minutes = &minutes
	} else {
		d.Minutes = nil
	}

	// seconds INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if secondsPresent {
		lb := int64(0)
		seconds, err := decoder.DecodeInteger(&lb, nil, false)
		if err != nil {
			return err
		}
		d.Seconds = &seconds
	} else {
		d.Seconds = nil
	}

	// fractional-part SEQUENCE { ... } OPTIONAL
	if fractionalPartPresent {
		d.FractionalPart = &DurationEquivalent_FractionalPart{}
		if err := d.FractionalPart.UnmarshalPER(decoder); err != nil {
			return err
		}
	} else {
		d.FractionalPart = nil
	}

	return nil
}

// UnmarshalAPER decodes the DurationEquivalent using Aligned Packed Encoding Rules (APER).
func (d *DurationEquivalent) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return d.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationEquivalent using Unaligned Packed Encoding Rules (UPER).
func (d *DurationEquivalent) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return d.UnmarshalPER(decoder)
}
