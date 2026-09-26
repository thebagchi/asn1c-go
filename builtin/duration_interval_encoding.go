package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// DurationIntervalEncoding_FractionalPart is the anonymous inline SEQUENCE
// type of DURATION-INTERVAL-ENCODING's "fractional-part" component.
//
//	SEQUENCE {
//	    number-of-digits INTEGER (1..3, ..., 4..MAX),  -- 3 bits
//	    fractional-value INTEGER (0..999, ..., 1000..MAX) -- 11 bits
//	}
type DurationIntervalEncoding_FractionalPart struct {
	NumberOfDigits  int64 `per:"lb=1,ub=3,ext"`
	FractionalValue int64 `per:"lb=0,ub=999,ext"`
}

// MarshalPER encodes the DurationIntervalEncoding_FractionalPart using
// Packed Encoding Rules onto encoder, so nested types can chain encoding
// onto a shared encoder. MarshalAPER/MarshalUPER create the encoder and
// call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationIntervalEncoding_FractionalPart) MarshalPER(
	encoder *per.Encoder,
) ([]byte, error) {
	// number-of-digits INTEGER (1..3, ..., 4..MAX) — constrained lb=1, ub=3, extensible
	if err := encoder.EncodeInteger(f.NumberOfDigits, CONSTRAINT_DIGITS); err != nil {
		return nil, err
	}

	// fractional-value INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	if err := encoder.EncodeInteger(f.FractionalValue, CONSTRAINT_FRACTION); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationIntervalEncoding_FractionalPart using Aligned Packed Encoding
// Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationIntervalEncoding_FractionalPart) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return f.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationIntervalEncoding_FractionalPart using Unaligned Packed Encoding
// Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationIntervalEncoding_FractionalPart) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return f.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationIntervalEncoding_FractionalPart using
// Packed Encoding Rules from decoder, so nested types can chain decoding
// off a shared decoder. UnmarshalAPER/UnmarshalUPER create the decoder and
// call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationIntervalEncoding_FractionalPart) UnmarshalPER(decoder *per.Decoder) error {
	// number-of-digits INTEGER (1..3, ..., 4..MAX) — constrained lb=1, ub=3, extensible
	numberOfDigits, err := decoder.DecodeInteger(CONSTRAINT_DIGITS)
	if err != nil {
		return err
	}

	f.NumberOfDigits = numberOfDigits

	// fractional-value INTEGER (0..999, ..., 1000..MAX) — constrained lb=0, ub=999, extensible
	fractionalValue, err := decoder.DecodeInteger(CONSTRAINT_FRACTION)
	if err != nil {
		return err
	}

	f.FractionalValue = fractionalValue

	return nil
}

// UnmarshalAPER decodes the DurationIntervalEncoding_FractionalPart using Aligned Packed Encoding
// Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationIntervalEncoding_FractionalPart) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return f.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationIntervalEncoding_FractionalPart using Unaligned Packed
// Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (f *DurationIntervalEncoding_FractionalPart) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
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
//	        number-of-digits INTEGER (1..3, ..., 4..MAX),  -- 3 bits
//	        fractional-value INTEGER (0..999, ..., 1000..MAX) -- 11 bits
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
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationIntervalEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	if err := d._MarshalPreamble(encoder); err != nil {
		return nil, err
	}

	if err := d._MarshalComponents(encoder); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the DurationIntervalEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationIntervalEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return d.MarshalPER(encoder)
}

// MarshalUPER encodes the DurationIntervalEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationIntervalEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return d.MarshalPER(encoder)
}

// UnmarshalPER decodes the DurationIntervalEncoding using Packed Encoding
// Rules from decoder, so nested types can chain decoding off a shared
// decoder. UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationIntervalEncoding) UnmarshalPER(decoder *per.Decoder) error {
	present, err := d._UnmarshalPreamble(decoder)
	if err != nil {
		return err
	}

	return d._UnmarshalComponents(decoder, present)
}

// UnmarshalAPER decodes the DurationIntervalEncoding using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationIntervalEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return d.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the DurationIntervalEncoding using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (d *DurationIntervalEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return d.UnmarshalPER(decoder)
}

// _MarshalPreamble writes the presence bit of every OPTIONAL component, per
// X.691 clause 19.2, before any component value.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of MarshalPER
func (d *DurationIntervalEncoding) _MarshalPreamble(encoder *per.Encoder) error {
	// X.691 clause 19.2: one bit per OPTIONAL component, in declaration order.
	for _, present := range []bool{
		d.Years != nil, d.Months != nil, d.Weeks != nil, d.Days != nil,
		d.Hours != nil, d.Minutes != nil, d.Seconds != nil, d.FractionalPart != nil,
	} {
		if err := encoder.EncodeBoolean(present); err != nil {
			return err
		}
	}

	return nil
}

// _MarshalComponents writes the components the preamble said were present, per
// X.691 clause 19.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of MarshalPER
func (d *DurationIntervalEncoding) _MarshalComponents(encoder *per.Encoder) error {
	if err := d._MarshalDate(encoder); err != nil {
		return err
	}

	return d._MarshalTime(encoder)
}

// _MarshalDate writes the years, months, weeks and days components.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of _MarshalComponents
func (d *DurationIntervalEncoding) _MarshalDate(encoder *per.Encoder) error {
	// years INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if d.Years != nil {
		if err := encoder.EncodeInteger(*d.Years, CONSTRAINT_DURATION_YEARS); err != nil {
			return err
		}
	}

	// months INTEGER (0..15, ..., 16..MAX) OPTIONAL — constrained lb=0, ub=15, extensible
	if d.Months != nil {
		err := encoder.EncodeInteger(*d.Months, CONSTRAINT_DURATION_MONTHS)
		if err != nil {
			return err
		}
	}

	// weeks INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if d.Weeks != nil {
		if err := encoder.EncodeInteger(*d.Weeks, CONSTRAINT_DURATION_WEEKS); err != nil {
			return err
		}
	}

	// days INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if d.Days != nil {
		if err := encoder.EncodeInteger(*d.Days, CONSTRAINT_DURATION_DAYS); err != nil {
			return err
		}
	}

	return nil
}

// _MarshalTime writes the hours, minutes, seconds and the fraction components.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of _MarshalComponents
func (d *DurationIntervalEncoding) _MarshalTime(encoder *per.Encoder) error {
	// hours INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if d.Hours != nil {
		if err := encoder.EncodeInteger(*d.Hours, CONSTRAINT_DURATION_HOURS); err != nil {
			return err
		}
	}

	// minutes INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if d.Minutes != nil {
		err := encoder.EncodeInteger(*d.Minutes, CONSTRAINT_DURATION_MINUTES)
		if err != nil {
			return err
		}
	}

	// seconds INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if d.Seconds != nil {
		err := encoder.EncodeInteger(*d.Seconds, CONSTRAINT_DURATION_SECONDS)
		if err != nil {
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
func (d *DurationIntervalEncoding) _UnmarshalPreamble(
	decoder *per.Decoder,
) (*_DurationPresence, error) {
	present := new(_DurationPresence)

	// X.691 clause 19.2: one bit per OPTIONAL component, in declaration order.
	for _, bit := range []*bool{
		&present.years, &present.months, &present.weeks, &present.days,
		&present.hours, &present.minutes, &present.seconds, &present.fraction,
	} {
		value, err := decoder.DecodeBoolean()
		if err != nil {
			return nil, err
		}

		*bit = value
	}

	return present, nil
}

// _UnmarshalComponents reads the components the preamble said were present, per
// X.691 clause 19.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of UnmarshalPER
func (d *DurationIntervalEncoding) _UnmarshalComponents(
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
func (d *DurationIntervalEncoding) _UnmarshalDate(
	decoder *per.Decoder,
	present *_DurationPresence,
) error {
	// years INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if present.years {
		years, err := decoder.DecodeInteger(CONSTRAINT_DURATION_YEARS)
		if err != nil {
			return err
		}

		d.Years = &years
	} else {
		d.Years = nil
	}

	// months INTEGER (0..15, ..., 16..MAX) OPTIONAL — constrained lb=0, ub=15, extensible
	if present.months {
		months, err := decoder.DecodeInteger(CONSTRAINT_DURATION_MONTHS)
		if err != nil {
			return err
		}

		d.Months = &months
	} else {
		d.Months = nil
	}

	// weeks INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if present.weeks {
		weeks, err := decoder.DecodeInteger(CONSTRAINT_DURATION_WEEKS)
		if err != nil {
			return err
		}

		d.Weeks = &weeks
	} else {
		d.Weeks = nil
	}

	// days INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if present.days {
		days, err := decoder.DecodeInteger(CONSTRAINT_DURATION_DAYS)
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
func (d *DurationIntervalEncoding) _UnmarshalTime(
	decoder *per.Decoder,
	present *_DurationPresence,
) error {
	// hours INTEGER (0..31, ..., 32..MAX) OPTIONAL — constrained lb=0, ub=31, extensible
	if present.hours {
		hours, err := decoder.DecodeInteger(CONSTRAINT_DURATION_HOURS)
		if err != nil {
			return err
		}

		d.Hours = &hours
	} else {
		d.Hours = nil
	}

	// minutes INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if present.minutes {
		minutes, err := decoder.DecodeInteger(CONSTRAINT_DURATION_MINUTES)
		if err != nil {
			return err
		}

		d.Minutes = &minutes
	} else {
		d.Minutes = nil
	}

	// seconds INTEGER (0..63, ..., 64..MAX) OPTIONAL — constrained lb=0, ub=63, extensible
	if present.seconds {
		seconds, err := decoder.DecodeInteger(CONSTRAINT_DURATION_SECONDS)
		if err != nil {
			return err
		}

		d.Seconds = &seconds
	} else {
		d.Seconds = nil
	}

	// fractional-part SEQUENCE { ... } OPTIONAL
	if present.fraction {
		d.FractionalPart = &DurationIntervalEncoding_FractionalPart{}
		if err := d.FractionalPart.UnmarshalPER(decoder); err != nil {
			return err
		}
	} else {
		d.FractionalPart = nil
	}

	return nil
}
