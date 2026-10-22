package per

import (
	"fmt"
	"time"
)

// _DateType is DATE-TYPE, X.691 32.11.7: a CHOICE of the date encodings of rows 1 to 14 of
// Table 2. A time.Time holds a date in full, so the codec uses two alternatives: row-7
// (DATE-ENCODING) for the years 0 to 9999, Year=Basic and Year=Proleptic (X.680 38.2.1 Table
// 6), and row-8 (ANY-DATE-ENCODING) for the other years. The other alternatives give
// ErrTimeValue when they are read. The components of the alternative are kept here.
type _DateType struct {
	choice int64
	year   int64
	month  int64
	day    int64
}

// _Set stores a date, and takes the alternative whose row holds the year (X.691 32.11.4).
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateType) _Set(
	year,
	month,
	day int64,
) {
	v.choice = TIME_DATE_ROW8

	if _InRow7(year) {
		v.choice = TIME_DATE_ROW7
	}

	v.year = year
	v.month = month
	v.day = day
}

// _Encode writes the index of the alternative, then the alternative, X.691 32.11.7.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateType) _Encode(e *Encoder) error {
	if err := e.EncodeChoiceId(
		v.choice,
		CONSTRAINT_TIME_DATE_TYPE,
	); err != nil {
		return err
	}

	if v.choice == TIME_DATE_ROW7 {
		var date _DateEncoding

		date._Set(
			v.year,
			v.month,
			v.day,
		)

		return date._Encode(e)
	}

	var date _AnyDateEncoding

	date._Set(
		v.year,
		v.month,
		v.day,
	)

	return date._Encode(e)
}

// _Decode reads the index of the alternative, then the alternative, X.691 32.11.7. A year that
// is not in the range of its row, and an alternative that is not row-7 or row-8, give
// ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateType) _Decode(d *Decoder) error {
	choice, err := d.DecodeChoiceId(CONSTRAINT_TIME_DATE_TYPE)
	if err != nil {
		return err
	}

	switch choice {
	case TIME_DATE_ROW7:
		var date _DateEncoding

		err = date._Decode(d)

		v.year = date.year
		v.month = date.month
		v.day = date.day
	case TIME_DATE_ROW8:
		var date _AnyDateEncoding

		err = date._Decode(d)

		v.year = date.year
		v.month = date.month
		v.day = date.day
	default:
		return fmt.Errorf(
			"DATE-TYPE row-%d is not a date of package time: %w",
			choice+TIME_DATE_FIRST_ROW,
			ErrTimeValue,
		)
	}

	v.choice = choice

	if err != nil {
		return err
	}

	return v._CheckRow()
}

// _CheckRow refuses a year that is not in the range of the row of the alternative: row-7 holds
// 0 to 9999 and row-8 holds the others (X.691 32.11.4).
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_DateType) _CheckRow() error {
	if _InRow7(v.year) != (v.choice == TIME_DATE_ROW7) {
		return fmt.Errorf(
			"year %d is not in the range of row-%d: %w",
			v.year,
			v.choice+TIME_DATE_FIRST_ROW,
			ErrTimeValue,
		)
	}

	return nil
}

// _InRow7 tells whether a year is one that row 7 of Table 2 holds, 0 to 9999.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _InRow7(year int64) bool {
	return year >= TIME_YEAR_ROW7_MIN && year <= TIME_YEAR_MAX
}

// _TimeType is TIME-TYPE, X.691 32.11.8: the number-of-digits, which is present if and only if
// the alternative is one of the rows 24 to 32 (32.11.9), and a CHOICE of the time encodings
// of rows 15 to 32 of Table 2. A time.Time holds an instant, so the codec uses the rows 22 and 23
// (whole seconds, UTC and a time difference) and the rows 31 and 32 (a fraction, UTC and a time
// difference). The other alternatives give ErrTimeValue when they are read, the local time
// without a difference of rows 21 and 30 among them. A zero digits stands for the absent
// number-of-digits. The components of the alternative are kept here.
type _TimeType struct {
	digits   int64
	choice   int64
	clock    time.Duration
	fraction int64
	offset   int64
}

// _Set stores the time of day of the wall clock of value and its offset, and takes the
// alternative that holds them: UTC or a time difference (X.691 32.11.4), with a fraction when
// the nanoseconds are not zero. The number of digits is the fewest (32.11.9).
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _Set(value time.Time) {
	_, seconds := value.Zone()

	v.clock = _Clock(value)
	v.offset = int64(seconds / TIME_MINUTE_SECONDS)
	v.digits = 0
	v.fraction = 0

	var (
		utc        = value.Location() == time.UTC
		fractional = value.Nanosecond() != 0
	)

	if fractional {
		var fraction _Fraction

		fraction._Set(int64(value.Nanosecond()))

		v.digits = fraction.digits
		v.fraction = fraction.value
	}

	switch {
	case utc && fractional:
		v.choice = TIME_CLOCK_ROW31
	case utc:
		v.choice = TIME_CLOCK_ROW22
	case fractional:
		v.choice = TIME_CLOCK_ROW32
	default:
		v.choice = TIME_CLOCK_ROW23
	}
}

// _Encode writes the preamble of one bit for number-of-digits (X.691 19.2), the digits if they
// are present, the index of the alternative and the alternative, X.691 32.11.8.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _Encode(e *Encoder) error {
	if err := e.EncodeBoolean(v.digits != 0); err != nil {
		return err
	}

	if v.digits != 0 {
		if err := e.EncodeInteger(
			v.digits,
			CONSTRAINT_TIME_DIGITS,
		); err != nil {
			return err
		}
	}

	if err := e.EncodeChoiceId(
		v.choice,
		CONSTRAINT_TIME_CLOCK_TYPE,
	); err != nil {
		return err
	}

	return v._EncodeClock(e)
}

// _EncodeClock writes the alternative of the time, X.691 32.3.8, 32.3.9, 32.3.17 and 32.3.18.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _EncodeClock(e *Encoder) error {
	switch v.choice {
	case TIME_CLOCK_ROW22:
		var row _TimeOfDayUTCEncoding

		row._Set(v.clock)

		return row._Encode(e)
	case TIME_CLOCK_ROW23:
		var row _TimeOfDayAndDiffEncoding

		row._Set(
			v.clock,
			v.offset,
		)

		return row._Encode(e)
	case TIME_CLOCK_ROW31:
		var row _TimeOfDayUTCAndFractionEncoding

		row._Set(
			v.clock,
			v.fraction,
		)

		return row._Encode(e)
	default:
		var row _TimeOfDayAndDiffAndFractionEncoding

		row._Set(
			v.clock,
			v.fraction,
			v.offset,
		)

		return row._Encode(e)
	}
}

// _Decode reads the preamble, the digits, the index of the alternative and the alternative,
// X.691 32.11.8. An alternative that is not row-22, row-23, row-31 or row-32, and a
// number-of-digits that is not present if and only if the alternative has a fraction (32.11.9),
// give ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _Decode(d *Decoder) error {
	*v = _TimeType{}

	present, err := d.DecodeBoolean()
	if err != nil {
		return err
	}

	if present {
		if v.digits, err = d.DecodeInteger(CONSTRAINT_TIME_DIGITS); err != nil {
			return err
		}
	}

	if v.choice, err = d.DecodeChoiceId(CONSTRAINT_TIME_CLOCK_TYPE); err != nil {
		return err
	}

	fractional := v.choice == TIME_CLOCK_ROW31 || v.choice == TIME_CLOCK_ROW32

	if present != fractional && v._Known() {
		return fmt.Errorf(
			"number-of-digits and the fraction of the alternative disagree: %w",
			ErrTimeValue,
		)
	}

	return v._DecodeClock(d)
}

// _Known tells whether the alternative is one that the codec reads.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _Known() bool {
	switch v.choice {
	case TIME_CLOCK_ROW22:
		fallthrough
	case TIME_CLOCK_ROW23:
		fallthrough
	case TIME_CLOCK_ROW31:
		fallthrough
	case TIME_CLOCK_ROW32:
		return true
	default:
		return false
	}
}

// _DecodeClock reads the alternative of the time, X.691 32.3.8, 32.3.9, 32.3.17 and 32.3.18,
// and keeps the time since midnight and the offset.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _DecodeClock(d *Decoder) error {
	var err error

	switch v.choice {
	case TIME_CLOCK_ROW22:
		var row _TimeOfDayUTCEncoding

		if err = row._Decode(d); err == nil {
			v.clock, err = row._Clock()
		}
	case TIME_CLOCK_ROW23:
		var row _TimeOfDayAndDiffEncoding

		if err = row._Decode(d); err == nil {
			v.clock, err = row._Clock()
		}

		if err == nil {
			v.offset, err = row._Offset()
		}
	case TIME_CLOCK_ROW31:
		var row _TimeOfDayUTCAndFractionEncoding

		if err = row._Decode(d); err == nil {
			v.clock, err = row._Clock(v.digits)
		}
	case TIME_CLOCK_ROW32:
		var row _TimeOfDayAndDiffAndFractionEncoding

		if err = row._Decode(d); err == nil {
			v.clock, err = row._Clock(v.digits)
		}

		if err == nil {
			v.offset, err = row._Offset()
		}
	default:
		err = fmt.Errorf(
			"TIME-TYPE row-%d is not a time of package time: %w",
			v.choice+TIME_CLOCK_FIRST_ROW,
			ErrTimeValue,
		)
	}

	return err
}

// _Location returns the location of the alternative: time.UTC for the rows 22 and 31, and a
// fixed zone of the offset for the rows 23 and 32. A zone of offset zero is a zone that is not
// time.UTC, as the time difference +00:00 is another abstract value than UTC (X.680 38.2.1).
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_TimeType) _Location() *time.Location {
	if v.choice == TIME_CLOCK_ROW22 || v.choice == TIME_CLOCK_ROW31 {
		return time.UTC
	}

	return time.FixedZone(
		"",
		int(v.offset*TIME_MINUTE_SECONDS),
	)
}

// _MixedDateTimeEncoding is DATE-TIME-ENCODING {DATE-TYPE, TIME-TYPE}, X.691 32.4.1 and
// 32.11.5: the date and the time of the instantiation for row 33 of Table 2.
type _MixedDateTimeEncoding struct {
	_DateType
	_TimeType
}

// _Set stores the date of value and the time of its wall clock.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
//   - 2026-10-21 21:48: takes the date from _CivilDate, an int64 year on any platform (review P31)
func (v *_MixedDateTimeEncoding) _Set(value time.Time) {
	var (
		civil _Civil
	)

	_CivilDate(
		value,
		&civil,
	)

	v._DateType._Set(
		civil.year,
		civil.month,
		civil.day,
	)
	v._TimeType._Set(value)
}

// _Encode writes date and time in the order of the SEQUENCE, X.691 32.4.1.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_MixedDateTimeEncoding) _Encode(e *Encoder) error {
	if err := v._DateType._Encode(e); err != nil {
		return err
	}

	return v._TimeType._Encode(e)
}

// _Decode reads date and time in the order of the SEQUENCE, X.691 32.4.1.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_MixedDateTimeEncoding) _Decode(d *Decoder) error {
	if err := v._DateType._Decode(d); err != nil {
		return err
	}

	return v._TimeType._Decode(d)
}

// _Time returns the instant of the date and the time. A day that its month does not have, and
// the clock of 24 hours, give ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_MixedDateTimeEncoding) _Time() (time.Time, error) {
	if err := _CheckBeforeMidnight(v.clock); err != nil {
		return time.Time{}, err
	}

	date, err := _MakeDate(
		v.year,
		v.month,
		v.day,
	)
	if err != nil {
		return time.Time{}, err
	}

	return _AtClock(
		date,
		v.clock,
		v._Location(),
	), nil
}

// _MixedEncoding is MIXED-ENCODING, X.691 32.11.5: a CHOICE of the 53 rows of Table 2. A TIME
// that a time.Time holds is row 33, so the codec reads and writes that alternative, and the
// other 52 give ErrTimeValue when they are read.
type _MixedEncoding struct {
	_MixedDateTimeEncoding
}

// _Set stores value as the alternative row-33.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_MixedEncoding) _Set(value time.Time) {
	v._MixedDateTimeEncoding._Set(value)
}

// _Encode writes the index of row-33 (6 bits, no extension marker, 53 alternatives), then the
// alternative, X.691 32.11.5 and clause 23.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_MixedEncoding) _Encode(e *Encoder) error {
	if err := e.EncodeChoiceId(
		TIME_MIXED_ROW33,
		CONSTRAINT_TIME_MIXED,
	); err != nil {
		return err
	}

	return v._MixedDateTimeEncoding._Encode(e)
}

// _Decode reads the index of the alternative, and the alternative if it is row-33, X.691
// 32.11.5. Another alternative gives ErrTimeValue, and is not read.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_MixedEncoding) _Decode(d *Decoder) error {
	choice, err := d.DecodeChoiceId(CONSTRAINT_TIME_MIXED)
	if err != nil {
		return err
	}

	if choice != TIME_MIXED_ROW33 {
		return fmt.Errorf(
			"MIXED-ENCODING row-%d is not a TIME of package time: %w",
			choice+TIME_MIXED_FIRST_ROW,
			ErrTimeValue,
		)
	}

	return v._MixedDateTimeEncoding._Decode(d)
}

// EncodeTime encodes a TIME with no constraint: MIXED-ENCODING (X.691 32.1.4 note 2, 32.11).
// The value is row 33 (DATE-TIME-ENCODING) with a DATE-TYPE of row 7 for the years 0 to 9999
// (Year=Basic or Proleptic) and row 8 for the other years, and with a TIME-TYPE of row 22 for
// time.UTC or row 23 for any other location (the offset is sent, also when it is zero), or rows
// 31 and 32 when the nanoseconds are not zero (32.11.8, 32.11.9: number-of-digits is the fewest
// digits, 1 to 9). An offset that is not whole minutes, or more than 15 hours from UTC (X.680
// 38.2.1 Local-or-UTC), wraps ErrTimeValue, and nothing is written.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (e *Encoder) EncodeTime(value time.Time) error {
	_, offset := value.Zone()

	if value.Location() != time.UTC &&
		(offset%TIME_MINUTE_SECONDS != 0 ||
			offset > TIME_OFFSET_MAX*TIME_MINUTE_SECONDS ||
			offset < -TIME_OFFSET_MAX*TIME_MINUTE_SECONDS) {
		return fmt.Errorf(
			"offset is not whole minutes within 15 hours of UTC (X.680 38.2.1): %w",
			ErrTimeValue,
		)
	}

	var mixed _MixedEncoding

	mixed._Set(value)

	return mixed._Encode(e)
}

// DecodeTime decodes a TIME that a time.Time holds in full: row 33 with a DATE-TYPE of row 7
// (years 0 to 9999) or row 8 (the other years), and a TIME-TYPE of row 22, 23, 31 or 32. Rows
// 22 and 31 give time.UTC. Rows 23 and 32 give a fixed zone of the offset, which is a zone that
// is not time.UTC also for an offset of zero. Every other row (the local time of rows 21 and 30
// has no offset, so no instant), a year outside the range of its row, a day that its month does
// not have, hours 24, seconds 60, a time difference of -00:00 or beyond 15 hours, and a fraction
// of more than 9 digits or one that does not fit its digits, wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (d *Decoder) DecodeTime() (time.Time, error) {
	var mixed _MixedEncoding

	if err := mixed._Decode(d); err != nil {
		return time.Time{}, err
	}

	return mixed._Time()
}
