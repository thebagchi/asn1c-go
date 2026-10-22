package per

import (
	"encoding/asn1"
	"fmt"
	"math/bits"
	"time"
)

// The bits of the preamble of DURATION-INTERVAL-ENCODING, X.691 32.6.1 and 19.2: one for each
// OPTIONAL component, in the order of the SEQUENCE, the first in the most significant bit of
// the octet.
const (
	DURATION_PREAMBLE_BITS   = 8
	DURATION_CLOCK_ELEMENTS  = 3
	DURATION_PRESENT_YEARS   = 0x80
	DURATION_PRESENT_MONTHS  = 0x40
	DURATION_PRESENT_WEEKS   = 0x20
	DURATION_PRESENT_DAYS    = 0x10
	DURATION_PRESENT_HOURS   = 0x08
	DURATION_PRESENT_MINUTES = 0x04
	DURATION_PRESENT_SECONDS = 0x02
	DURATION_PRESENT_FRAC    = 0x01
	DURATION_PRESENT_DATE    = DURATION_PRESENT_YEARS | DURATION_PRESENT_MONTHS |
		DURATION_PRESENT_WEEKS | DURATION_PRESENT_DAYS
	DURATION_PRESENT_CLOCK = DURATION_PRESENT_HOURS | DURATION_PRESENT_MINUTES |
		DURATION_PRESENT_SECONDS
)

// _DurationIntervalEncoding is DURATION-INTERVAL-ENCODING, X.691 32.6.1: eight OPTIONAL
// components, years, months, weeks, days, hours, minutes, seconds and the fractional-part
// (number-of-digits and fractional-value). The codec uses the hours, the minutes, the seconds
// and the fractional-part: a time.Duration has no years, months, weeks or days (their length is
// not fixed, X.680 38.2.4), so the codec does not write them and refuses them when it reads.
type _DurationIntervalEncoding struct {
	present uint8
	hours   int64
	minutes int64
	seconds int64
	_Fraction
}

// _Set stores the hours, the minutes, the seconds and the fraction of value. A time element
// that is zero is present only if it is the least significant element, or has a fraction
// (X.691 32.6.3). The fraction has the fewest digits (X.691 32.6.5). value is not negative.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _Set(value time.Duration) {
	*v = _DurationIntervalEncoding{}

	var (
		whole = int64(value / time.Second)
		nanos = int64(value % time.Second)
	)

	v.hours = whole / (TIME_HOUR_MINUTES * TIME_MINUTE_SECONDS)
	v.minutes = whole / TIME_MINUTE_SECONDS % TIME_HOUR_MINUTES
	v.seconds = whole % TIME_MINUTE_SECONDS

	if v.hours != 0 {
		v.present |= DURATION_PRESENT_HOURS
	}

	if v.minutes != 0 {
		v.present |= DURATION_PRESENT_MINUTES
	}

	if v.seconds != 0 || nanos != 0 || v.present&DURATION_PRESENT_CLOCK == 0 {
		v.present |= DURATION_PRESENT_SECONDS
	}

	if nanos != 0 {
		v.present |= DURATION_PRESENT_FRAC

		v._Fraction._Set(nanos)
	}
}

// _Encode writes the preamble of eight bits, then the components that are present in the order
// of the SEQUENCE, X.691 32.6.1 and 19.2.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _Encode(e *Encoder) error {
	octet := [1]byte{v.present}

	if err := e.EncodePreamble(&asn1.BitString{
		Bytes:     octet[:],
		BitLength: DURATION_PREAMBLE_BITS,
	}); err != nil {
		return err
	}

	if err := v._EncodeClock(e); err != nil {
		return err
	}

	if v.present&DURATION_PRESENT_FRAC == 0 {
		return nil
	}

	if err := e.EncodeInteger(
		v.digits,
		CONSTRAINT_DURATION_DIGITS,
	); err != nil {
		return err
	}

	return e.EncodeInteger(
		v.value,
		CONSTRAINT_TIME_FRACTION,
	)
}

// _EncodeClock writes the hours, the minutes and the seconds that are present, X.691 32.6.1.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _EncodeClock(e *Encoder) error {
	if v.present&DURATION_PRESENT_HOURS != 0 {
		if err := e.EncodeInteger(
			v.hours,
			CONSTRAINT_DURATION_HOURS,
		); err != nil {
			return err
		}
	}

	if v.present&DURATION_PRESENT_MINUTES != 0 {
		if err := e.EncodeInteger(
			v.minutes,
			CONSTRAINT_DURATION_MINUTES,
		); err != nil {
			return err
		}
	}

	if v.present&DURATION_PRESENT_SECONDS == 0 {
		return nil
	}

	return e.EncodeInteger(
		v.seconds,
		CONSTRAINT_DURATION_SECONDS,
	)
}

// _Decode reads the preamble, and the components that it says are present, X.691 32.6.1. The
// years, months, weeks and days give ErrTimeValue before any component is read.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _Decode(d *Decoder) error {
	var octet [1]byte

	preamble := asn1.BitString{
		Bytes:     octet[:],
		BitLength: DURATION_PREAMBLE_BITS,
	}

	if err := d.DecodePreamble(&preamble); err != nil {
		return err
	}

	*v = _DurationIntervalEncoding{
		present: octet[0],
	}

	if v.present&DURATION_PRESENT_DATE != 0 {
		return fmt.Errorf(
			"duration has years, months, weeks or days (X.680 38.2.4): %w",
			ErrTimeValue,
		)
	}

	if err := v._DecodeClock(d); err != nil {
		return err
	}

	if v.present&DURATION_PRESENT_FRAC == 0 {
		return nil
	}

	digits, err := d.DecodeInteger(CONSTRAINT_DURATION_DIGITS)
	if err != nil {
		return err
	}

	value, err := d.DecodeInteger(CONSTRAINT_TIME_FRACTION)
	if err != nil {
		return err
	}

	v.digits = digits
	v.value = value

	return nil
}

// _DecodeClock reads the hours, the minutes and the seconds that are present, X.691 32.6.1.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _DecodeClock(d *Decoder) error {
	var err error

	if v.present&DURATION_PRESENT_HOURS != 0 {
		if v.hours, err = d.DecodeInteger(CONSTRAINT_DURATION_HOURS); err != nil {
			return err
		}
	}

	if v.present&DURATION_PRESENT_MINUTES != 0 {
		if v.minutes, err = d.DecodeInteger(CONSTRAINT_DURATION_MINUTES); err != nil {
			return err
		}
	}

	if v.present&DURATION_PRESENT_SECONDS != 0 {
		v.seconds, err = d.DecodeInteger(CONSTRAINT_DURATION_SECONDS)
	}

	return err
}

// _Duration returns the length of the elements that are present, with the fraction in the least
// significant one. No element, a negative element, and a total beyond a time.Duration give
// ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _Duration() (time.Duration, error) {
	if v.present&DURATION_PRESENT_CLOCK == 0 {
		return 0, fmt.Errorf(
			"duration has no element (X.680 38.3.6): %w",
			ErrTimeValue,
		)
	}

	total, unit, err := v._Elements()
	if err != nil {
		return 0, err
	}

	fraction, err := v._Nanos(unit)
	if err != nil {
		return 0, err
	}

	total, err = _AddNanos(
		total,
		int64(fraction),
		1,
	)
	if err != nil {
		return 0, err
	}

	return time.Duration(total), nil
}

// _Elements returns the length of the hours, the minutes and the seconds that are present in
// nanoseconds, and the length of the least significant one that is present.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DurationIntervalEncoding) _Elements() (uint64, uint64, error) {
	var (
		total uint64
		unit  uint64
		err   error
	)

	var (
		flags = [DURATION_CLOCK_ELEMENTS]uint8{
			DURATION_PRESENT_HOURS,
			DURATION_PRESENT_MINUTES,
			DURATION_PRESENT_SECONDS,
		}
		values = [DURATION_CLOCK_ELEMENTS]int64{
			v.hours,
			v.minutes,
			v.seconds,
		}
		units = [DURATION_CLOCK_ELEMENTS]uint64{
			uint64(time.Hour),
			uint64(time.Minute),
			uint64(time.Second),
		}
	)

	for index, flag := range flags {
		if v.present&flag == 0 {
			continue
		}

		total, err = _AddNanos(
			total,
			values[index],
			units[index],
		)
		if err != nil {
			return 0, 0, err
		}

		unit = units[index]
	}

	return total, unit, nil
}

// _AddNanos adds value elements of unit nanoseconds to total. A negative value, and a sum
// beyond what a time.Duration holds, give ErrTimeValue. The numbers in the text are decoded
// ones.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _AddNanos(
	total uint64,
	value int64,
	unit uint64,
) (uint64, error) {
	var (
		high, low = bits.Mul64(
			uint64(value),
			unit,
		)

		sum, carry = bits.Add64(
			total,
			low,
			0,
		)
	)

	if value < 0 || high != 0 || carry != 0 || sum > TIME_NANOS_MAX {
		return 0, fmt.Errorf(
			"duration element %d does not fit a time.Duration: %w",
			value,
			ErrTimeValue,
		)
	}

	return sum, nil
}

// EncodeDuration encodes a DURATION: Table 2 row 37, DURATION-INTERVAL-ENCODING (X.691
// 32.6.1). Only the elements hours, minutes and seconds are used. The elements that are not
// zero are present, and the least significant one is present even when it is zero (32.6.3); the
// fraction of a second has the fewest digits (32.6.5). A negative value wraps ErrTimeValue, and
// nothing is written.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (e *Encoder) EncodeDuration(value time.Duration) error {
	if value < 0 {
		return fmt.Errorf(
			"duration is negative (X.680 38.3.6, no sign): %w",
			ErrTimeValue,
		)
	}

	var duration _DurationIntervalEncoding

	duration._Set(value)

	return duration._Encode(e)
}

// DecodeDuration decodes a DURATION. The elements years, months, weeks and days wrap
// ErrTimeValue: their length is not fixed (X.680 38.2.4). So does a fraction that is not a
// whole number of nanoseconds, a value that does not fit a time.Duration, and a value with no
// element.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (d *Decoder) DecodeDuration() (time.Duration, error) {
	var duration _DurationIntervalEncoding

	if err := duration._Decode(d); err != nil {
		return 0, err
	}

	return duration._Duration()
}
