package per

import (
	"strconv"
	"testing"
	"time"
)

// This file is an internal test because the calendar arithmetic is unexported.

// CIVIL_SPAN_DAYS is how many days each side of 1970-01-01 the sweep checks: past 1582,
// year 0 and 9999. CIVIL_FAR_YEARS are years past what a 32-bit int holds, and the edges
// of the TIME vectors.
const (
	CIVIL_SPAN_DAYS = 3_000_000
)

var (
	CIVIL_FAR_YEARS = []int64{
		-292277022000,
		-2147483649,
		-1,
		0,
		1582,
		1970,
		9999,
		2147483648,
		292277026595,
	}
)

// TestCivil_MatchesTime guards review P31 (user: int64 inside): on a 64-bit platform
// time.Date is exact, so it is the reference. Every day of the sweep goes to a date and
// back, and each far year, on 1 January, 28 and 29 February and 31 December, must give the
// day count that time.Date gives.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation (review P31)
func TestCivil_MatchesTime(t *testing.T) {
	if strconv.IntSize < UINT64_BITS {
		t.Skip("time.Date takes an int year, so it is no reference on a 32-bit platform")
	}

	for days := int64(-CIVIL_SPAN_DAYS); days <= CIVIL_SPAN_DAYS; days++ {
		_CheckCivilDay(
			t,
			days,
		)
	}

	for _, year := range CIVIL_FAR_YEARS {
		for _, month := range []time.Month{
			time.January,
			time.February,
			time.December,
		} {
			start := time.Date(
				int(year),
				month,
				1,
				0,
				0,
				0,
				0,
				time.UTC,
			)
			_CheckCivilDay(
				t,
				_FloorDiv(
					start.Unix(),
					SECONDS_PER_DAY,
				),
			)
		}
	}
}

// _CheckCivilDay compares one day count with time.Date, in both directions.
//
// Revisions:
//   - 2026-10-21 21:48: initial creation
func _CheckCivilDay(
	t *testing.T,
	days int64,
) {
	t.Helper()

	var (
		date _Civil
		want = time.Unix(
			days*SECONDS_PER_DAY,
			0,
		).UTC()
	)

	_CivilFromDays(
		days,
		&date,
	)

	year, month, day := want.Date()
	if date.year != int64(year) || date.month != int64(month) || date.day != int64(day) {
		t.Fatalf(
			"day %d: %d-%d-%d, want %d-%d-%d",
			days,
			date.year,
			date.month,
			date.day,
			year,
			month,
			day,
		)
	}

	if back := _DaysFromCivil(&date); back != days {
		t.Fatalf(
			"%d-%d-%d: day %d, want %d",
			date.year,
			date.month,
			date.day,
			back,
			days,
		)
	}
}
