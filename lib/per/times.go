package per

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"time"
)

// ErrTimeValue is what the codecs of the time types report for a value that the Go type cannot
// hold, on both sides: a value outside the abstract values of the type (X.680 38.4), and an
// encoding of a value that a time.Time or a time.Duration cannot keep.
var (
	ErrTimeValue = errors.New("value is not a value of the time type")
)

// The year ranges of X.680 38.2.1 Table 6 and the clock limits of X.680 38.4.2, 38.4.3.
// DATE and DATE-TIME have Year=Basic (1582 to 9999). The date of row 7 of X.691 Table 2 holds
// Year=Basic and Year=Proleptic (0 to 9999); row 8 holds all the other years.
const (
	TIME_YEAR_BASIC_MIN    = 1582
	TIME_YEAR_ROW7_MIN     = 0
	TIME_YEAR_MAX          = 9999
	TIME_MONTH_MIN         = 1
	TIME_MONTH_MAX         = 12
	TIME_DAY_MIN           = 1
	TIME_DAY_MAX           = 31
	TIME_HOURS_MAX         = 24
	TIME_MINUTES_MAX       = 59
	TIME_SECONDS_MAX       = 60
	TIME_FRACTION_ROOT_MAX = 999
	TIME_FRACTION_DIGITS   = 9
	TIME_DIFFERENCE_HOURS  = 15
	TIME_HOUR_MINUTES      = 60
	TIME_OFFSET_MAX        = TIME_DIFFERENCE_HOURS * TIME_HOUR_MINUTES
	TIME_IMMEDIATE_MIN     = 2005
	TIME_IMMEDIATE_MAX     = 2020
	TIME_FUTURE_MIN        = 2021
	TIME_FUTURE_MAX        = 2276
	TIME_PAST_MIN          = 1749
	TIME_PAST_MAX          = 2004
	TIME_DATE_CHOICES      = 14
	TIME_CLOCK_CHOICES     = 18
	TIME_MIXED_CHOICES     = 53
	DURATION_HOURS_ROOT    = 31
	DURATION_SIXTY_ROOT    = 63
	DURATION_DIGITS_ROOT   = 3
	TIME_MINUTE_SECONDS    = 60
	TIME_POWER_MAX         = 19
	TIME_NANOS_MAX         = math.MaxInt64
)

// The alternatives of the CHOICE types, as the index that X.691 23.6 and 23.7 encode. The
// index of row-n of DATE-TYPE is n-1. The index of row-n of TIME-TYPE is n-15. The index of
// row-n of MIXED-ENCODING is n-1.
const (
	TIME_YEAR_IMMEDIATE      = 0
	TIME_YEAR_NEAR_FUTURE    = 1
	TIME_YEAR_NEAR_PAST      = 2
	TIME_YEAR_REMAINDER      = 3
	TIME_DATE_ROW7           = 6
	TIME_DATE_ROW8           = 7
	TIME_CLOCK_ROW21         = 6
	TIME_CLOCK_ROW22         = 7
	TIME_CLOCK_ROW23         = 8
	TIME_CLOCK_ROW30         = 15
	TIME_CLOCK_ROW31         = 16
	TIME_CLOCK_ROW32         = 17
	TIME_MIXED_ROW33         = 32
	TIME_DATE_FIRST_ROW      = 1
	TIME_CLOCK_FIRST_ROW     = 15
	TIME_MIXED_FIRST_ROW     = 1
	TIME_DIFFERENCE_POSITIVE = 0
	TIME_DIFFERENCE_NEGATIVE = 1
)

// The constraints of the associated types of X.691 clause 32, shared by every call. The text of
// each is in specs/builtin.asn1.
var (
	CONSTRAINT_TIME_YEAR_CHOICE = Constrained(
		0,
		TIME_YEAR_REMAINDER,
	)
	CONSTRAINT_TIME_YEAR_IMMEDIATE = Constrained(
		TIME_IMMEDIATE_MIN,
		TIME_IMMEDIATE_MAX,
	)
	CONSTRAINT_TIME_YEAR_NEAR_FUTURE = Constrained(
		TIME_FUTURE_MIN,
		TIME_FUTURE_MAX,
	)
	CONSTRAINT_TIME_YEAR_NEAR_PAST = Constrained(
		TIME_PAST_MIN,
		TIME_PAST_MAX,
	)
	CONSTRAINT_TIME_YEAR_ANY = Unconstrained()
	CONSTRAINT_TIME_MONTH    = Constrained(
		TIME_MONTH_MIN,
		TIME_MONTH_MAX,
	)
	CONSTRAINT_TIME_DAY = Constrained(
		TIME_DAY_MIN,
		TIME_DAY_MAX,
	)
	CONSTRAINT_TIME_HOURS = Constrained(
		0,
		TIME_HOURS_MAX,
	)
	CONSTRAINT_TIME_MINUTES = Constrained(
		0,
		TIME_MINUTES_MAX,
	)
	CONSTRAINT_TIME_SECONDS = Constrained(
		0,
		TIME_SECONDS_MAX,
	)
	CONSTRAINT_TIME_FRACTION = Constrained(
		0,
		TIME_FRACTION_ROOT_MAX,
	).Extensible()
	CONSTRAINT_TIME_DIFFERENCE_SIGN = Constrained(
		0,
		TIME_DIFFERENCE_NEGATIVE,
	)
	CONSTRAINT_TIME_DIFFERENCE_HOURS = Constrained(
		0,
		TIME_DIFFERENCE_HOURS,
	)
	CONSTRAINT_TIME_DIFFERENCE_MINS = Constrained(
		1,
		TIME_MINUTES_MAX,
	)
	CONSTRAINT_TIME_DIGITS    = SemiConstrained(1)
	CONSTRAINT_TIME_DATE_TYPE = Constrained(
		0,
		TIME_DATE_CHOICES-1,
	)
	CONSTRAINT_TIME_CLOCK_TYPE = Constrained(
		0,
		TIME_CLOCK_CHOICES-1,
	)
	CONSTRAINT_TIME_MIXED = Constrained(
		0,
		TIME_MIXED_CHOICES-1,
	)
	CONSTRAINT_DURATION_HOURS = Constrained(
		0,
		DURATION_HOURS_ROOT,
	).Extensible()
	CONSTRAINT_DURATION_MINUTES = Constrained(
		0,
		DURATION_SIXTY_ROOT,
	).Extensible()
	CONSTRAINT_DURATION_SECONDS = Constrained(
		0,
		DURATION_SIXTY_ROOT,
	).Extensible()
	CONSTRAINT_DURATION_DIGITS = Constrained(
		1,
		DURATION_DIGITS_ROOT,
	).Extensible()
)

// _CheckBasicYear refuses a value whose year is not 1582 to 9999, the years of Year=Basic
// (X.680 38.2.1 Table 6, 38.4.1, 38.4.3). The text has no value in it.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
//   - 2026-10-21 21:48: reads the year from _CivilDate; Year gives an int (review P31)
func _CheckBasicYear(value time.Time) error {
	var (
		civil _Civil
	)

	_CivilDate(
		value,
		&civil,
	)

	year := civil.year

	if year < TIME_YEAR_BASIC_MIN || year > TIME_YEAR_MAX {
		return fmt.Errorf(
			"year is not in 1582 to 9999 (Year=Basic, X.680 38.2.1): %w",
			ErrTimeValue,
		)
	}

	return nil
}

// _CheckWholeSeconds refuses a value that has a fraction of a second. DATE-TIME and
// TIME-OF-DAY have the property setting Time=HMS (X.680 38.4.2, 38.4.3), with no fraction.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _CheckWholeSeconds(value time.Duration) error {
	if value%time.Second != 0 {
		return fmt.Errorf(
			"time of day has a fraction of a second (X.680 38.4.2, Time=HMS): %w",
			ErrTimeValue,
		)
	}

	return nil
}

// _Clock returns the time since midnight of the wall clock of value, in its own location.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _Clock(value time.Time) time.Duration {
	hours, minutes, seconds := value.Clock()

	return time.Duration(hours)*time.Hour +
		time.Duration(minutes)*time.Minute +
		time.Duration(seconds)*time.Second +
		time.Duration(value.Nanosecond())
}

// _MakeDate builds the midnight of a date in time.UTC from the three components that a decoder
// read. A day that its month does not have gives ErrTimeValue (X.680 38.4.1, Date=YMD), as does
// a year that a time.Time cannot hold. The date goes through int64 days, so a year past the
// platform int works on a 32-bit platform too. The numbers in the text are decoded ones.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
//   - 2026-10-21 21:48: checks the date and builds the midnight through int64 days, in place of
//     time.Date with an int year (review P31)
func _MakeDate(
	year,
	month,
	day int64,
) (time.Time, error) {
	inRange := year > -TIME_YEAR_LIMIT && year < TIME_YEAR_LIMIT && month >= 1 &&
		month <= CIVIL_MONTHS && day >= 1
	if !inRange {
		return time.Time{}, fmt.Errorf(
			"date %d-%d-%d: %w",
			year,
			month,
			day,
			ErrTimeValue,
		)
	}

	var (
		date = _Civil{
			year:  year,
			month: month,
			day:   day,
		}
		days = _DaysFromCivil(&date)
		back _Civil
	)

	_CivilFromDays(
		days,
		&back,
	)

	if back != date || days < TIME_DAYS_MIN || days > TIME_DAYS_MAX {
		return time.Time{}, fmt.Errorf(
			"date %d-%d-%d is not in the calendar: %w",
			year,
			month,
			day,
			ErrTimeValue,
		)
	}

	return time.Unix(
		days*SECONDS_PER_DAY,
		0,
	).UTC(), nil
}

// _AtClock gives the wall clock clock (under 24 hours) of the day of date, in loc. A decoder
// calls it after _MakeDate has checked the day. While the year fits the platform int it is
// time.Date, which picks the offset of loc as it always did, a summer-time gap included.
// A later year (a 32-bit platform) goes through the Unix seconds of the day, with the offset
// of loc at that instant.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
//   - 2026-10-21 21:48: a year past the platform int goes through the Unix seconds (review P31)
func _AtClock(
	date time.Time,
	clock time.Duration,
	loc *time.Location,
) time.Time {
	var (
		civil _Civil
	)

	_CivilDate(
		date,
		&civil,
	)

	if int64(int(civil.year)) != civil.year {
		return _AtClockLate(
			date,
			clock,
			loc,
		)
	}

	return time.Date(
		date.Year(),
		date.Month(),
		date.Day(),
		int(clock/time.Hour),
		int(clock%time.Hour/time.Minute),
		int(clock%time.Minute/time.Second),
		int(clock%time.Second),
		loc,
	)
}

// _MakeClock builds the time since midnight from the hours, minutes and seconds that a
// decoder read. Seconds 60 is a leap second, which a time.Duration cannot tell from the next
// minute. Hours 24 is the midnight at the end of the day (X.680 38.4.2 note) and only with
// minutes and seconds zero. The numbers in the text are decoded ones.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _MakeClock(
	hours,
	minutes,
	seconds int64,
) (time.Duration, error) {
	end := hours == TIME_HOURS_MAX && (minutes != 0 || seconds != 0)

	if seconds == TIME_SECONDS_MAX || end {
		return 0, fmt.Errorf(
			"time of day %d:%d:%d is not a time of day of package time: %w",
			hours,
			minutes,
			seconds,
			ErrTimeValue,
		)
	}

	return time.Duration(hours)*time.Hour +
		time.Duration(minutes)*time.Minute +
		time.Duration(seconds)*time.Second, nil
}

// _CheckBeforeMidnight refuses the clock of 24 hours: a time.Time has no end of the day, only
// the start of the next one, so a date and a clock of 24:00:00 is another date.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _CheckBeforeMidnight(clock time.Duration) error {
	if clock >= TIME_HOURS_MAX*time.Hour {
		return fmt.Errorf(
			"time of day is the midnight at the end of the day: %w",
			ErrTimeValue,
		)
	}

	return nil
}

// _PowerOfTen returns 10 to the power n, for n up to 19, the widest power in a uint64.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _PowerOfTen(n int64) uint64 {
	power := uint64(1)

	for range n {
		power *= DECIMAL_BASE
	}

	return power
}

// _Fraction is the pair of a fractional part of X.691 32.3.10 to 32.3.18, 32.6.5 and 32.11.9:
// the number of digits N, and the fraction multiplied by ten to the power N.
type _Fraction struct {
	digits int64
	value  int64
}

// _Set takes the fewest digits for a fraction of a second of nanos nanoseconds, 1 to
// 999999999: the trailing zeros are left out (X.691 32.6.5, 32.11.9).
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_Fraction) _Set(nanos int64) {
	v.digits = TIME_FRACTION_DIGITS
	v.value = nanos

	for v.value%DECIMAL_BASE == 0 {
		v.value /= DECIMAL_BASE
		v.digits--
	}
}

// _Nanos returns the fraction as a number of nanoseconds of an element of unit nanoseconds
// (one second for TIME, the least significant element for DURATION). A fraction that has a
// negative value, fewer than one digit, a value of ten to the power N or more, or a value that
// is not a whole number of nanoseconds gives ErrTimeValue. A zero value is zero at any digits.
// The numbers in the text are decoded ones.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_Fraction) _Nanos(unit uint64) (uint64, error) {
	if v.value == 0 {
		return 0, nil
	}

	var (
		digits = v.digits
		value  = uint64(v.value)
	)

	for value%DECIMAL_BASE == 0 && digits > 0 {
		value /= DECIMAL_BASE
		digits--
	}

	if !v._Fits(
		value,
		digits,
	) {
		return 0, fmt.Errorf(
			"fraction %d of %d digits: %w",
			v.value,
			v.digits,
			ErrTimeValue,
		)
	}

	return v._Scale(
		value,
		digits,
		unit,
	)
}

// _Scale returns value, which has digits digits, as a number of nanoseconds of an element of
// unit nanoseconds: value times unit, divided by ten to the power digits. A quotient that is
// not whole gives ErrTimeValue. The loop ends at the first remainder, in 33 steps at most:
// the product has 33 digits at most, and a whole quotient is not zero.
//
// Revisions:
//   - 2026-10-19 16:17: initial creation
func (v *_Fraction) _Scale(
	value uint64,
	digits int64,
	unit uint64,
) (uint64, error) {
	high, low := bits.Mul64(
		value,
		unit,
	)

	for range digits {
		var remainder uint64

		high, remainder = bits.Div64(
			0,
			high,
			DECIMAL_BASE,
		)
		low, remainder = bits.Div64(
			remainder,
			low,
			DECIMAL_BASE,
		)

		if remainder != 0 {
			return 0, fmt.Errorf(
				"fraction %d of %d digits is not whole nanoseconds: %w",
				v.value,
				v.digits,
				ErrTimeValue,
			)
		}
	}

	return low, nil
}

// _Fits tells whether the fraction is a fraction: not negative, at least one digit, and below
// ten to the power N. value and digits are the value and the digits without the trailing zeros.
// A value of 19 digits or more is below ten to the power N, which a uint64 cannot hold.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_Fraction) _Fits(
	value uint64,
	digits int64,
) bool {
	if v.value < 0 || v.digits < 1 {
		return false
	}

	return digits > TIME_POWER_MAX || value < _PowerOfTen(digits)
}

// _AtClockLate is _AtClock for a year past the platform int. The wall clock is the Unix
// seconds of the day plus clock, less the offset of loc; the offset is read at the guess and
// read again once, so a change of offset at that instant is taken into account.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation (review P31)
func _AtClockLate(
	date time.Time,
	clock time.Duration,
	loc *time.Location,
) time.Time {
	var (
		wall  = date.Unix() + int64(clock/time.Second)
		nanos = int64(clock % time.Second)
	)

	var (
		_, offset = time.Unix(
			wall,
			nanos,
		).In(loc).Zone()
		value = time.Unix(
			wall-int64(offset),
			nanos,
		).In(loc)
	)

	if _, again := value.Zone(); again != offset {
		value = time.Unix(
			wall-int64(again),
			nanos,
		).In(loc)
	}

	return value
}
