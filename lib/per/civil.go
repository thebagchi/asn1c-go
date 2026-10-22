package per

import (
	"math"
	"time"
)

// The proleptic Gregorian calendar in days since 1970-01-01, with int64 years. time.Time
// gives its year as an int, which is 32 bits on a 32-bit platform, so a year past 2^31 needs
// this arithmetic there. The method counts years from 1 March, so that the leap day is the
// last day of a year: an era is 400 years of 146097 days, a year 365 days, a leap year every
// 4 years but not every 100 years, and the months from March run in a pattern of 153 days to
// 5 months.
const (
	CIVIL_EPOCH_DAYS      = 719468 // days from 0000-03-01 to 1970-01-01
	CIVIL_ERA_DAYS        = 146097 // days in 400 years
	CIVIL_ERA_YEARS       = 400
	CIVIL_CENTURY_DAYS    = 36524 // days in 100 years that hold 24 leap days
	CIVIL_LEAP_CYCLE_DAYS = 1460  // days in 4 years before the leap day
	CIVIL_YEAR_DAYS       = 365
	CIVIL_LEAP_YEARS      = 4
	CIVIL_CENTURY_YEARS   = 100
	CIVIL_MONTH_SPAN      = 153 // days in five months from March
	CIVIL_MONTH_RUN       = 5
	CIVIL_MONTH_ROUND     = 2
	CIVIL_MARCH           = 3  // the first month of a year of this method
	CIVIL_JANUARY_SHIFT   = 9  // January and February are months 10 and 11 from March
	CIVIL_MONTHS          = 12 // months in a year
	SECONDS_PER_DAY       = 86400
)

// TIME_DAYS_MIN and TIME_DAYS_MAX are the days since 1970-01-01 whose midnight a time.Time
// can hold: the Unix seconds of a whole day must fit an int64. TIME_YEAR_LIMIT is a year far
// enough past that range that a year inside it cannot overflow the day count.
const (
	TIME_DAYS_MIN   = math.MinInt64/SECONDS_PER_DAY + 1
	TIME_DAYS_MAX   = math.MaxInt64/SECONDS_PER_DAY - 1
	TIME_YEAR_LIMIT = 1 << 40
)

// _Civil is a date of the proleptic Gregorian calendar.
type _Civil struct {
	year  int64
	month int64
	day   int64
}

// _CivilDate sets date to the date of the wall clock of value in its location. It reads the
// Unix seconds and the offset of the zone at that instant, so the year is an int64 on any
// platform, where value.Date would give an int. The caller owns date, so it stays on the
// caller's stack.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation (review P31, user: int64 inside)
func _CivilDate(
	value time.Time,
	date *_Civil,
) {
	var (
		_, offset = value.Zone()
		seconds   = value.Unix() + int64(offset)
	)

	_CivilFromDays(
		_FloorDiv(
			seconds,
			SECONDS_PER_DAY,
		),
		date,
	)
}

// _CivilFromDays sets date to the day that is days after 1970-01-01.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation (review P31, user: int64 inside)
func _CivilFromDays(
	days int64,
	date *_Civil,
) {
	var (
		shifted = days + CIVIL_EPOCH_DAYS
		era     = _FloorDiv(
			shifted,
			CIVIL_ERA_DAYS,
		)
		inEra  = shifted - era*CIVIL_ERA_DAYS
		inYear = (inEra - inEra/CIVIL_LEAP_CYCLE_DAYS + inEra/CIVIL_CENTURY_DAYS -
			inEra/(CIVIL_ERA_DAYS-1)) / CIVIL_YEAR_DAYS
		inDays = inEra - (CIVIL_YEAR_DAYS*inYear + inYear/CIVIL_LEAP_YEARS -
			inYear/CIVIL_CENTURY_YEARS)
		march = (CIVIL_MONTH_RUN*inDays + CIVIL_MONTH_ROUND) / CIVIL_MONTH_SPAN
	)

	date.year = inYear + era*CIVIL_ERA_YEARS
	date.month = (march+CIVIL_MARCH-1)%CIVIL_MONTHS + 1
	date.day = inDays - (CIVIL_MONTH_SPAN*march+CIVIL_MONTH_ROUND)/CIVIL_MONTH_RUN + 1

	if date.month < CIVIL_MARCH {
		date.year++
	}
}

// _DaysFromCivil returns how many days after 1970-01-01 a date is. The month must be 1 to 12;
// a day past the end of its month gives a day of the next month, which _MakeDate refuses.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation (review P31, user: int64 inside)
func _DaysFromCivil(date *_Civil) int64 {
	year := date.year
	if date.month < CIVIL_MARCH {
		year--
	}

	var (
		era = _FloorDiv(
			year,
			CIVIL_ERA_YEARS,
		)
		inEra  = year - era*CIVIL_ERA_YEARS
		march  = (date.month + CIVIL_JANUARY_SHIFT) % CIVIL_MONTHS
		inYear = (CIVIL_MONTH_SPAN*march+CIVIL_MONTH_ROUND)/CIVIL_MONTH_RUN + date.day - 1
		leaps  = inEra/CIVIL_LEAP_YEARS - inEra/CIVIL_CENTURY_YEARS
		days   = inEra*CIVIL_YEAR_DAYS + leaps + inYear
	)

	return era*CIVIL_ERA_DAYS + days - CIVIL_EPOCH_DAYS
}

// _FloorDiv divides and rounds toward minus infinity, which the calendar needs for a date
// before 1970 or before year 0.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation (review P31, user: int64 inside)
func _FloorDiv(
	value,
	divisor int64,
) int64 {
	quotient := value / divisor
	if value%divisor != 0 && (value < 0) != (divisor < 0) {
		quotient--
	}

	return quotient
}
