package per

import (
	"fmt"
	"time"
)

// _TimeDifference is TIME-DIFFERENCE, X.691 32.3.3: the sign (an ENUMERATED), the hours (0 to
// 15) and the minutes (1 to 59), which are OPTIONAL and left out when they are zero. A minutes
// of zero here stands for the absent component.
type _TimeDifference struct {
	sign    int64
	hours   int64
	minutes int64
}

// _Set splits an offset from UTC in minutes into the sign, the hours and the minutes. An
// offset of zero is positive.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeDifference) _Set(offset int64) {
	v.sign = TIME_DIFFERENCE_POSITIVE

	if offset < 0 {
		v.sign = TIME_DIFFERENCE_NEGATIVE
		offset = -offset
	}

	v.hours = offset / TIME_HOUR_MINUTES
	v.minutes = offset % TIME_HOUR_MINUTES
}

// _Encode writes the preamble of one bit for the OPTIONAL minutes (X.691 19.2), then the
// components in the order of the SEQUENCE: sign, hours and minutes, X.691 32.3.3.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeDifference) _Encode(e *Encoder) error {
	if err := e.EncodeBoolean(v.minutes != 0); err != nil {
		return err
	}

	if err := e.EncodeEnumerated(
		uint64(v.sign),
		CONSTRAINT_TIME_DIFFERENCE_SIGN,
	); err != nil {
		return err
	}

	if err := e.EncodeInteger(
		v.hours,
		CONSTRAINT_TIME_DIFFERENCE_HOURS,
	); err != nil {
		return err
	}

	if v.minutes == 0 {
		return nil
	}

	return e.EncodeInteger(
		v.minutes,
		CONSTRAINT_TIME_DIFFERENCE_MINS,
	)
}

// _Decode reads the preamble and the components of X.691 32.3.3.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeDifference) _Decode(d *Decoder) error {
	present, err := d.DecodeBoolean()
	if err != nil {
		return err
	}

	sign, err := d.DecodeEnumerated(CONSTRAINT_TIME_DIFFERENCE_SIGN)
	if err != nil {
		return err
	}

	hours, err := d.DecodeInteger(CONSTRAINT_TIME_DIFFERENCE_HOURS)
	if err != nil {
		return err
	}

	v.sign = int64(sign)
	v.hours = hours
	v.minutes = 0

	if !present {
		return nil
	}

	minutes, err := d.DecodeInteger(CONSTRAINT_TIME_DIFFERENCE_MINS)
	if err != nil {
		return err
	}

	v.minutes = minutes

	return nil
}

// _Offset returns the offset from UTC in minutes. A difference beyond 15 hours is not an
// abstract value (X.680 38.2.1, Local-or-UTC=LD, -15 to +15 hours). A negative zero is the
// local time of UTC without a sign (X.680 38.2.1), which package time does not have.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeDifference) _Offset() (int64, error) {
	offset := v.hours*TIME_HOUR_MINUTES + v.minutes

	if offset > TIME_OFFSET_MAX || offset == 0 && v.sign == TIME_DIFFERENCE_NEGATIVE {
		return 0, fmt.Errorf(
			"time difference of sign %d, %d hours, %d minutes: %w",
			v.sign,
			v.hours,
			v.minutes,
			ErrTimeValue,
		)
	}

	if v.sign == TIME_DIFFERENCE_NEGATIVE {
		return -offset, nil
	}

	return offset, nil
}

// _TimeOfDayEncoding is TIME-OF-DAY-ENCODING, X.691 32.3.7: the hours (0 to 24), the minutes
// (0 to 59) and the seconds (0 to 60), 5 bits each.
type _TimeOfDayEncoding struct {
	hours   int64
	minutes int64
	seconds int64
}

// _Set splits a time since midnight into the hours, the minutes and the seconds. The part of
// a second is not stored.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayEncoding) _Set(clock time.Duration) {
	v.hours = int64(clock / time.Hour)
	v.minutes = int64(clock % time.Hour / time.Minute)
	v.seconds = int64(clock % time.Minute / time.Second)
}

// _Encode writes the three components in the order of the SEQUENCE, X.691 32.3.7.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayEncoding) _Encode(e *Encoder) error {
	if err := e.EncodeInteger(
		v.hours,
		CONSTRAINT_TIME_HOURS,
	); err != nil {
		return err
	}

	if err := e.EncodeInteger(
		v.minutes,
		CONSTRAINT_TIME_MINUTES,
	); err != nil {
		return err
	}

	return e.EncodeInteger(
		v.seconds,
		CONSTRAINT_TIME_SECONDS,
	)
}

// _Decode reads the three components in the order of the SEQUENCE, X.691 32.3.7.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayEncoding) _Decode(d *Decoder) error {
	hours, err := d.DecodeInteger(CONSTRAINT_TIME_HOURS)
	if err != nil {
		return err
	}

	minutes, err := d.DecodeInteger(CONSTRAINT_TIME_MINUTES)
	if err != nil {
		return err
	}

	seconds, err := d.DecodeInteger(CONSTRAINT_TIME_SECONDS)
	if err != nil {
		return err
	}

	v.hours = hours
	v.minutes = minutes
	v.seconds = seconds

	return nil
}

// _Clock returns the time since midnight, or ErrTimeValue for a value that package time does
// not have (see _MakeClock).
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayEncoding) _Clock() (time.Duration, error) {
	return _MakeClock(
		v.hours,
		v.minutes,
		v.seconds,
	)
}

// _TimeOfDayUTCEncoding is TIME-OF-DAY-UTC-ENCODING, X.691 32.3.8: the same SEQUENCE as
// TIME-OF-DAY-ENCODING, for a time that is UTC.
type _TimeOfDayUTCEncoding _TimeOfDayEncoding

// _Set splits a time since midnight into the hours, the minutes and the seconds.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCEncoding) _Set(clock time.Duration) {
	(*_TimeOfDayEncoding)(v)._Set(clock)
}

// _Encode writes the three components, X.691 32.3.8.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCEncoding) _Encode(e *Encoder) error {
	return (*_TimeOfDayEncoding)(v)._Encode(e)
}

// _Decode reads the three components, X.691 32.3.8.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCEncoding) _Decode(d *Decoder) error {
	return (*_TimeOfDayEncoding)(v)._Decode(d)
}

// _Clock returns the time since midnight, see _TimeOfDayEncoding.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCEncoding) _Clock() (time.Duration, error) {
	return (*_TimeOfDayEncoding)(v)._Clock()
}

// _TimeOfDayAndDiffEncoding is TIME-OF-DAY-AND-DIFF-ENCODING, X.691 32.3.9: the local time as
// the SEQUENCE of TIME-OF-DAY-ENCODING, and the time difference.
type _TimeOfDayAndDiffEncoding struct {
	_TimeOfDayEncoding
	_TimeDifference
}

// _Set stores the local time since midnight and the offset from UTC in minutes.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayAndDiffEncoding) _Set(
	clock time.Duration,
	offset int64,
) {
	v._TimeOfDayEncoding._Set(clock)
	v._TimeDifference._Set(offset)
}

// _Encode writes local-time and time-difference, X.691 32.3.9.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayAndDiffEncoding) _Encode(e *Encoder) error {
	if err := v._TimeOfDayEncoding._Encode(e); err != nil {
		return err
	}

	return v._TimeDifference._Encode(e)
}

// _Decode reads local-time and time-difference, X.691 32.3.9.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayAndDiffEncoding) _Decode(d *Decoder) error {
	if err := v._TimeOfDayEncoding._Decode(d); err != nil {
		return err
	}

	return v._TimeDifference._Decode(d)
}

// _TimeOfDayAndFractionEncoding is TIME-OF-DAY-AND-FRACTION-ENCODING, X.691 32.3.16: the
// hours, the minutes and the seconds of TIME-OF-DAY-ENCODING, and the fraction of the seconds,
// INTEGER (0..999, ..., 1000..MAX), which is 11 bits for up to three digits.
type _TimeOfDayAndFractionEncoding struct {
	_TimeOfDayEncoding
	fraction int64
}

// _Set splits a time since midnight into the hours, the minutes and the seconds, and stores
// the fraction that _Fraction made of the nanoseconds.
//
// Revisions:
//   - 2026-10-19 16:17: initial creation
func (v *_TimeOfDayAndFractionEncoding) _Set(
	clock time.Duration,
	fraction int64,
) {
	v._TimeOfDayEncoding._Set(clock)

	v.fraction = fraction
}

// _Encode writes the four components in the order of the SEQUENCE, X.691 32.3.16.
//
// Revisions:
//   - 2026-10-19 16:17: initial creation
func (v *_TimeOfDayAndFractionEncoding) _Encode(e *Encoder) error {
	if err := v._TimeOfDayEncoding._Encode(e); err != nil {
		return err
	}

	return e.EncodeInteger(
		v.fraction,
		CONSTRAINT_TIME_FRACTION,
	)
}

// _Decode reads the four components in the order of the SEQUENCE, X.691 32.3.16.
//
// Revisions:
//   - 2026-10-19 16:17: initial creation
func (v *_TimeOfDayAndFractionEncoding) _Decode(d *Decoder) error {
	if err := v._TimeOfDayEncoding._Decode(d); err != nil {
		return err
	}

	fraction, err := d.DecodeInteger(CONSTRAINT_TIME_FRACTION)
	if err != nil {
		return err
	}

	v.fraction = fraction

	return nil
}

// _Clock returns the time since midnight with the fraction of digits digits. A fraction of
// more than 9 digits is not a whole number of nanoseconds unless it is zero, and gives
// ErrTimeValue, as does any other value that package time does not have (see _Fraction).
//
// Revisions:
//   - 2026-10-19 16:17: initial creation
func (v *_TimeOfDayAndFractionEncoding) _Clock(digits int64) (time.Duration, error) {
	clock, err := v._TimeOfDayEncoding._Clock()
	if err != nil {
		return 0, err
	}

	if v.fraction != 0 && digits > TIME_FRACTION_DIGITS {
		return 0, fmt.Errorf(
			"fraction of %d digits: %w",
			digits,
			ErrTimeValue,
		)
	}

	var fraction = _Fraction{
		digits: digits,
		value:  v.fraction,
	}

	nanos, err := fraction._Nanos(uint64(time.Second))
	if err != nil {
		return 0, err
	}

	return clock + time.Duration(nanos), nil
}

// _TimeOfDayUTCAndFractionEncoding is TIME-OF-DAY-UTC-AND-FRACTION-ENCODING, X.691 32.3.17:
// the same SEQUENCE as TIME-OF-DAY-AND-FRACTION-ENCODING, for a time that is UTC.
type _TimeOfDayUTCAndFractionEncoding _TimeOfDayAndFractionEncoding

// _Set stores the time since midnight and the fraction.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCAndFractionEncoding) _Set(
	clock time.Duration,
	fraction int64,
) {
	(*_TimeOfDayAndFractionEncoding)(v)._Set(
		clock,
		fraction,
	)
}

// _Encode writes the four components, X.691 32.3.17.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCAndFractionEncoding) _Encode(e *Encoder) error {
	return (*_TimeOfDayAndFractionEncoding)(v)._Encode(e)
}

// _Decode reads the four components, X.691 32.3.17.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCAndFractionEncoding) _Decode(d *Decoder) error {
	return (*_TimeOfDayAndFractionEncoding)(v)._Decode(d)
}

// _Clock returns the time since midnight, see _TimeOfDayAndFractionEncoding.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayUTCAndFractionEncoding) _Clock(digits int64) (time.Duration, error) {
	return (*_TimeOfDayAndFractionEncoding)(v)._Clock(digits)
}

// _TimeOfDayAndDiffAndFractionEncoding is TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING, X.691
// 32.3.18: the local time as the SEQUENCE of TIME-OF-DAY-AND-FRACTION-ENCODING, and the time
// difference.
type _TimeOfDayAndDiffAndFractionEncoding struct {
	_TimeOfDayAndFractionEncoding
	_TimeDifference
}

// _Set stores the local time since midnight, the fraction and the offset from UTC in minutes.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayAndDiffAndFractionEncoding) _Set(
	clock time.Duration,
	fraction,
	offset int64,
) {
	v._TimeOfDayAndFractionEncoding._Set(
		clock,
		fraction,
	)
	v._TimeDifference._Set(offset)
}

// _Encode writes local-time and time-difference, X.691 32.3.18.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayAndDiffAndFractionEncoding) _Encode(e *Encoder) error {
	if err := v._TimeOfDayAndFractionEncoding._Encode(e); err != nil {
		return err
	}

	return v._TimeDifference._Encode(e)
}

// _Decode reads local-time and time-difference, X.691 32.3.18.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeOfDayAndDiffAndFractionEncoding) _Decode(d *Decoder) error {
	if err := v._TimeOfDayAndFractionEncoding._Decode(d); err != nil {
		return err
	}

	return v._TimeDifference._Decode(d)
}

// EncodeTimeOfDay encodes a TIME-OF-DAY: Table 2 row 21, TIME-OF-DAY-ENCODING (X.691 32.3.7).
// value is the time since midnight, 0 to 24h in whole seconds; 24h is the midnight at the end
// of the day (X.680 38.4.2 note). Any other value wraps ErrTimeValue, and nothing is written.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (e *Encoder) EncodeTimeOfDay(value time.Duration) error {
	if value < 0 || value > TIME_HOURS_MAX*time.Hour {
		return fmt.Errorf(
			"time of day is not 0 to 24 hours (X.680 38.4.2): %w",
			ErrTimeValue,
		)
	}

	if err := _CheckWholeSeconds(value); err != nil {
		return err
	}

	var clock _TimeOfDayEncoding

	clock._Set(value)

	return clock._Encode(e)
}

// DecodeTimeOfDay decodes a TIME-OF-DAY. Hours 24 with minutes and seconds not zero, and
// seconds 60 (a leap second, which a time.Duration cannot tell from 24:00:00), wrap
// ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (d *Decoder) DecodeTimeOfDay() (time.Duration, error) {
	var clock _TimeOfDayEncoding

	if err := clock._Decode(d); err != nil {
		return 0, err
	}

	return clock._Clock()
}
