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
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationEquivalent_FractionalPart) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// number-of-digits INTEGER (1..MAX) — semi-constrained lb=1
	if err := encoder.EncodeInteger(f.NumberOfDigits, CONSTRAINT_AT_LEAST_ONE); err != nil {
		return nil, err
	}

	// fractional-value INTEGER (0..MAX) — semi-constrained lb=0
	if err := encoder.EncodeInteger(f.FractionalValue, CONSTRAINT_NON_NEGATIVE); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationEquivalent_FractionalPart using Aligned Packed Encoding Rules
// (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationEquivalent_FractionalPart) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return f.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationEquivalent_FractionalPart using Unaligned Packed Encoding Rules
// (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationEquivalent_FractionalPart) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return f.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationEquivalent_FractionalPart using Packed
// Encoding Rules from decoder, so nested types can chain decoding off a
// shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call
// this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationEquivalent_FractionalPart) UnmarshalPER(decoder *per.Decoder) error {
	// number-of-digits INTEGER (1..MAX) — semi-constrained lb=1
	numberOfDigits, err := decoder.DecodeInteger(CONSTRAINT_AT_LEAST_ONE)
	if err != nil {
		return err
	}

	f.NumberOfDigits = numberOfDigits

	// fractional-value INTEGER (0..MAX) — semi-constrained lb=0
	fractionalValue, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
	if err != nil {
		return err
	}

	f.FractionalValue = fractionalValue

	return nil
}

// UnmarshalAPER decodes the DurationEquivalent_FractionalPart using Aligned Packed Encoding Rules
// (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationEquivalent_FractionalPart) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return f.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationEquivalent_FractionalPart using Unaligned Packed Encoding
// Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationEquivalent_FractionalPart) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
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
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationEquivalent) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	if err := d._MarshalPreamble(encoder); err != nil {
		return nil, err
	}

	if err := d._MarshalComponents(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationEquivalent using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationEquivalent) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return d.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationEquivalent using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationEquivalent) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return d.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationEquivalent using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationEquivalent) UnmarshalPER(decoder *per.Decoder) error {
	present, err := d._UnmarshalPreamble(decoder)
	if err != nil {
		return err
	}

	return d._UnmarshalComponents(decoder, present)
}

// UnmarshalAPER decodes the DurationEquivalent using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationEquivalent) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return d.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationEquivalent using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationEquivalent) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return d.UnmarshalPER(decoder)
}

// _MarshalPreamble writes the presence bit of every OPTIONAL component, per
// X.691 clause 19.2, before any component value.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of MarshalPER
func (d *DurationEquivalent) _MarshalPreamble(encoder *per.Encoder) error {
	// Root preamble (X.691 19.2-19.3): one presence bit per OPTIONAL
	// component, in declaration order, before any component value.
	if err := encoder.EncodeBoolean(d.Years != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.Months != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.Weeks != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.Days != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.Hours != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.Minutes != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.Seconds != nil); err != nil {
		return err
	}

	if err := encoder.EncodeBoolean(d.FractionalPart != nil); err != nil {
		return err
	}

	return nil
}

// _MarshalComponents writes the components the preamble said were present, per
// X.691 clause 19.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of MarshalPER
func (d *DurationEquivalent) _MarshalComponents(encoder *per.Encoder) error {
	if err := d._MarshalDate(encoder); err != nil {
		return err
	}

	return d._MarshalTime(encoder)
}

// _MarshalDate writes the years, months, weeks and days components.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of _MarshalComponents
func (d *DurationEquivalent) _MarshalDate(encoder *per.Encoder) error {
	// years INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Years != nil {
		if err := encoder.EncodeInteger(*d.Years, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	// months INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Months != nil {
		if err := encoder.EncodeInteger(*d.Months, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	// weeks INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Weeks != nil {
		if err := encoder.EncodeInteger(*d.Weeks, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	// days INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Days != nil {
		if err := encoder.EncodeInteger(*d.Days, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	return nil
}

// _MarshalTime writes the hours, minutes, seconds and the fraction components.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of _MarshalComponents
func (d *DurationEquivalent) _MarshalTime(encoder *per.Encoder) error {
	// hours INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Hours != nil {
		if err := encoder.EncodeInteger(*d.Hours, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	// minutes INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Minutes != nil {
		if err := encoder.EncodeInteger(*d.Minutes, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	// seconds INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if d.Seconds != nil {
		if err := encoder.EncodeInteger(*d.Seconds, CONSTRAINT_NON_NEGATIVE); err != nil {
			return err
		}
	}

	// fractional-part SEQUENCE { ... } OPTIONAL
	if d.FractionalPart != nil {
		if _, err := d.FractionalPart.MarshalPER(encoder); err != nil {
			return err
		}
	}

	return nil
}

// _UnmarshalPreamble reads the presence bit of every OPTIONAL component, per
// X.691 clause 19.2.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of UnmarshalPER
func (d *DurationEquivalent) _UnmarshalPreamble(decoder *per.Decoder) (*_DurationPresence, error) {
	// Root preamble (X.691 19.2-19.3): one presence bit per OPTIONAL
	// component, in declaration order, before any component value.
	yearsPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	monthsPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	weeksPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	daysPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	hoursPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	minutesPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	secondsPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	fractionalPartPresent, err := decoder.DecodeBoolean()
	if err != nil {
		return nil, err
	}

	return &_DurationPresence{
		years:    yearsPresent,
		months:   monthsPresent,
		weeks:    weeksPresent,
		days:     daysPresent,
		hours:    hoursPresent,
		minutes:  minutesPresent,
		seconds:  secondsPresent,
		fraction: fractionalPartPresent,
	}, nil
}

// _UnmarshalComponents reads the components the preamble said were present, per
// X.691 clause 19.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of UnmarshalPER
func (d *DurationEquivalent) _UnmarshalComponents(
	decoder *per.Decoder,
	present *_DurationPresence,
) error {
	if err := d._UnmarshalDate(decoder, present); err != nil {
		return err
	}

	return d._UnmarshalTime(decoder, present)
}

// _UnmarshalDate reads the years, months, weeks and days components.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of _UnmarshalComponents
func (d *DurationEquivalent) _UnmarshalDate(
	decoder *per.Decoder,
	present *_DurationPresence,
) error {
	// years INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.years {
		years, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Years = &years
	} else {
		d.Years = nil
	}

	// months INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.months {
		months, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Months = &months
	} else {
		d.Months = nil
	}

	// weeks INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.weeks {
		weeks, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Weeks = &weeks
	} else {
		d.Weeks = nil
	}

	// days INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.days {
		days, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Days = &days
	} else {
		d.Days = nil
	}

	return nil
}

// _UnmarshalTime reads the hours, minutes, seconds and the fraction components.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of _UnmarshalComponents
func (d *DurationEquivalent) _UnmarshalTime(
	decoder *per.Decoder,
	present *_DurationPresence,
) error {
	// hours INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.hours {
		hours, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Hours = &hours
	} else {
		d.Hours = nil
	}

	// minutes INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.minutes {
		minutes, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Minutes = &minutes
	} else {
		d.Minutes = nil
	}

	// seconds INTEGER (0..MAX) OPTIONAL — semi-constrained lb=0
	if present.seconds {
		seconds, err := decoder.DecodeInteger(CONSTRAINT_NON_NEGATIVE)
		if err != nil {
			return err
		}

		d.Seconds = &seconds
	} else {
		d.Seconds = nil
	}

	// fractional-part SEQUENCE { ... } OPTIONAL
	if present.fraction {
		d.FractionalPart = &DurationEquivalent_FractionalPart{}
		if err := d.FractionalPart.UnmarshalPER(decoder); err != nil {
			return err
		}
	} else {
		d.FractionalPart = nil
	}

	return nil
}
