package per

import (
	"fmt"
	"time"
)

// _DateEncoding is DATE-ENCODING, X.691 32.2.7: the year of YEAR-ENCODING, the month (1 to 12,
// 4 bits) and the day (1 to 31, 5 bits).
type _DateEncoding struct {
	_YearEncoding
	month int64
	day   int64
}

// _Set stores the year, the month and the day.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateEncoding) _Set(
	year,
	month,
	day int64,
) {
	v._YearEncoding._Set(year)
	v.month = month
	v.day = day
}

// _Encode writes the three components in the order of the SEQUENCE, X.691 32.2.7. It has no
// optional component, so it has no preamble.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateEncoding) _Encode(e *Encoder) error {
	if err := v._YearEncoding._Encode(e); err != nil {
		return err
	}

	if err := e.EncodeInteger(
		v.month,
		CONSTRAINT_TIME_MONTH,
	); err != nil {
		return err
	}

	return e.EncodeInteger(
		v.day,
		CONSTRAINT_TIME_DAY,
	)
}

// _Decode reads the three components in the order of the SEQUENCE, X.691 32.2.7.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateEncoding) _Decode(d *Decoder) error {
	if err := v._YearEncoding._Decode(d); err != nil {
		return err
	}

	month, err := d.DecodeInteger(CONSTRAINT_TIME_MONTH)
	if err != nil {
		return err
	}

	day, err := d.DecodeInteger(CONSTRAINT_TIME_DAY)
	if err != nil {
		return err
	}

	v.month = month
	v.day = day

	return nil
}

// _AnyDateEncoding is ANY-DATE-ENCODING, X.691 32.2.8: the year as an unconstrained INTEGER,
// the month and the day as in DATE-ENCODING.
type _AnyDateEncoding struct {
	_AnyYearEncoding
	month int64
	day   int64
}

// _Set stores the year, the month and the day.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_AnyDateEncoding) _Set(
	year,
	month,
	day int64,
) {
	v._AnyYearEncoding._Set(year)
	v.month = month
	v.day = day
}

// _Encode writes the three components in the order of the SEQUENCE, X.691 32.2.8.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_AnyDateEncoding) _Encode(e *Encoder) error {
	if err := v._AnyYearEncoding._Encode(e); err != nil {
		return err
	}

	if err := e.EncodeInteger(
		v.month,
		CONSTRAINT_TIME_MONTH,
	); err != nil {
		return err
	}

	return e.EncodeInteger(
		v.day,
		CONSTRAINT_TIME_DAY,
	)
}

// _Decode reads the three components in the order of the SEQUENCE, X.691 32.2.8.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_AnyDateEncoding) _Decode(d *Decoder) error {
	if err := v._AnyYearEncoding._Decode(d); err != nil {
		return err
	}

	month, err := d.DecodeInteger(CONSTRAINT_TIME_MONTH)
	if err != nil {
		return err
	}

	day, err := d.DecodeInteger(CONSTRAINT_TIME_DAY)
	if err != nil {
		return err
	}

	v.month = month
	v.day = day

	return nil
}

// EncodeDate encodes a DATE: Table 2 row 7, DATE-ENCODING (X.691 32.2.7). The date is the
// year, month and day of value in its own location, and its clock must be midnight there. The
// year is 1582 to 9999 (X.680 38.4.1: Year=Basic). A value outside these limits wraps
// ErrTimeValue, and nothing is written.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
//   - 2026-10-21 21:48: takes the date from _CivilDate, so a year past the platform int encodes
//     on a 32-bit platform too (review P31)
func (e *Encoder) EncodeDate(value time.Time) error {
	if err := _CheckBasicYear(value); err != nil {
		return err
	}

	if _Clock(value) != 0 {
		return fmt.Errorf(
			"date is not at midnight of its location (X.680 38.4.1, Date=YMD): %w",
			ErrTimeValue,
		)
	}

	var (
		civil _Civil
		date  _DateEncoding
	)

	_CivilDate(
		value,
		&civil,
	)
	date._Set(
		civil.year,
		civil.month,
		civil.day,
	)

	return date._Encode(e)
}

// DecodeDate decodes a DATE. The result is midnight of the date in time.UTC. A year outside
// 1582 to 9999, or a day that the month does not have, wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (d *Decoder) DecodeDate() (time.Time, error) {
	var date _DateEncoding

	if err := date._Decode(d); err != nil {
		return time.Time{}, err
	}

	if date.year < TIME_YEAR_BASIC_MIN || date.year > TIME_YEAR_MAX {
		return time.Time{}, fmt.Errorf(
			"year %d is not in 1582 to 9999 (Year=Basic, X.680 38.4.1): %w",
			date.year,
			ErrTimeValue,
		)
	}

	return _MakeDate(
		date.year,
		date.month,
		date.day,
	)
}
