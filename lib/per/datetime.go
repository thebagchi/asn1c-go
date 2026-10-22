package per

import (
	"fmt"
	"time"
)

// _DateTimeEncoding is DATE-TIME-ENCODING {DATE-ENCODING, TIME-OF-DAY-ENCODING}, X.691 32.4.1
// and 32.4.2: the date and the time of the instantiation for the rows 7 and 21 of Table 2.
type _DateTimeEncoding struct {
	_DateEncoding
	_TimeOfDayEncoding
}

// _Set stores the date of value and the time of day of its wall clock.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
//   - 2026-10-21 21:48: takes the date from _CivilDate, an int64 year on any platform (review P31)
func (v *_DateTimeEncoding) _Set(value time.Time) {
	var (
		civil _Civil
	)

	_CivilDate(
		value,
		&civil,
	)

	v._DateEncoding._Set(
		civil.year,
		civil.month,
		civil.day,
	)
	v._TimeOfDayEncoding._Set(_Clock(value))
}

// _Encode writes date and time in the order of the SEQUENCE, X.691 32.4.1.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateTimeEncoding) _Encode(e *Encoder) error {
	if err := v._DateEncoding._Encode(e); err != nil {
		return err
	}

	return v._TimeOfDayEncoding._Encode(e)
}

// _Decode reads date and time in the order of the SEQUENCE, X.691 32.4.1.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateTimeEncoding) _Decode(d *Decoder) error {
	if err := v._DateEncoding._Decode(d); err != nil {
		return err
	}

	return v._TimeOfDayEncoding._Decode(d)
}

// EncodeDateTime encodes a DATE-TIME: Table 2 row 33 with rows 7 and 21, DATE-TIME-ENCODING
// (X.691 32.4.1, 32.4.2). The value is the wall clock of value in its own location (the
// Local-or-UTC setting is L: there is no offset), in whole seconds, with a year of 1582 to
// 9999. Any other value wraps ErrTimeValue, and nothing is written.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (e *Encoder) EncodeDateTime(value time.Time) error {
	if err := _CheckBasicYear(value); err != nil {
		return err
	}

	if value.Nanosecond() != 0 {
		return fmt.Errorf(
			"date and time have a fraction of a second (X.680 38.4.3, Time=HMS): %w",
			ErrTimeValue,
		)
	}

	var dateTime _DateTimeEncoding

	dateTime._Set(value)

	return dateTime._Encode(e)
}

// DecodeDateTime decodes a DATE-TIME. The result is the wall clock in time.UTC (the type has
// no offset). Hours 24 and seconds 60 wrap ErrTimeValue, as a time.Time cannot hold them.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (d *Decoder) DecodeDateTime() (time.Time, error) {
	var dateTime _DateTimeEncoding

	if err := dateTime._Decode(d); err != nil {
		return time.Time{}, err
	}

	year := dateTime.year

	if year < TIME_YEAR_BASIC_MIN || year > TIME_YEAR_MAX {
		return time.Time{}, fmt.Errorf(
			"year %d is not in 1582 to 9999 (Year=Basic, X.680 38.4.3): %w",
			year,
			ErrTimeValue,
		)
	}

	clock, err := dateTime._Clock()
	if err != nil {
		return time.Time{}, err
	}

	if err := _CheckBeforeMidnight(clock); err != nil {
		return time.Time{}, err
	}

	date, err := _MakeDate(
		year,
		dateTime.month,
		dateTime.day,
	)
	if err != nil {
		return time.Time{}, err
	}

	return _AtClock(
		date,
		clock,
		time.UTC,
	), nil
}
