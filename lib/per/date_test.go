package per_test

import (
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _P9DateCodec is DATE: Table 2 row 7, DATE-ENCODING (X.691 32.2.7), the type of X.680 38.4.1
// (Date=YMD, Year=Basic). A caller encodes a time.Time whose clock is midnight in its own
// location; the date is the date in that location. The decoder gives midnight in time.UTC.
//
// Revisions:
//   - 2026-10-19 16:02: initial creation
func _P9DateCodec() *_P9Codec[time.Time] {
	return &_P9Codec[time.Time]{
		name: "EncodeDate",
		encode: func(
			enc *per.Encoder,
			value time.Time,
		) error {
			return enc.EncodeDate(value)
		},
		decode: func(dec *per.Decoder) (time.Time, error) {
			return dec.DecodeDate()
		},
		value: func(
			t *testing.T,
			row *_P9Row,
		) time.Time {
			t.Helper()

			return time.Date(
				int(row.Year),
				time.Month(row.Month),
				row.Day,
				0,
				0,
				0,
				0,
				_P9Zone(
					t,
					row.Zone,
				),
			)
		},
		want: func(
			t *testing.T,
			row *_P9Row,
		) time.Time {
			t.Helper()

			return time.Date(
				int(row.Year),
				time.Month(row.Month),
				row.Day,
				0,
				0,
				0,
				0,
				time.UTC,
			)
		},
		same: _P9Wall,
		zero: time.Time.IsZero,
	}
}

// TestDate_Vectors checks EncodeDate and DecodeDate against the octets of the oracles for
// DATE-ENCODING (X.691 32.2.7): YEAR-ENCODING (32.2.3, a CHOICE of 2 bits whose alternatives
// hold 2005..2020, 2021..2276, 1749..2004 and the rest), month 1..12 in 4 bits, day 1..31 in 5
// bits. The rows cover the year ranges at their edges, leap days and zones: the date is the date
// of the value in its own zone.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDate_Vectors(t *testing.T) {
	_P9Vectors(
		t,
		_P9DateCodec(),
		_P9Load(t).Date,
	)
}

// TestDate_Framed writes each DATE between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDate_Framed(t *testing.T) {
	_P9Framed(
		t,
		_P9DateCodec(),
		_P9Load(t).Date,
	)
}

// TestDate_Truncated cuts each DATE encoding short.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDate_Truncated(t *testing.T) {
	_P9Truncated(
		t,
		_P9DateCodec(),
		_P9Load(t).Date,
	)
}

// TestDate_DecodeRefusals decodes encodings of DATE-ENCODING that are not values of DATE: a year
// outside 1582..9999 (X.680 38.2.1: the Basic year; 1581 and below are Proleptic, 10000 and above
// are Large, and X.680 38.4.1 has Year=Basic only), and a day that its month does not have. The
// error wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDate_DecodeRefusals(t *testing.T) {
	_P9DecodeRefusals(
		t,
		_P9DateCodec(),
		_P9Load(t).RefuseDate,
	)
}

// TestDate_EncodeRefusals checks the values that EncodeDate refuses: a year outside 1582..9999
// (also the zero time.Time, year 1), and a clock that is not midnight in the location of the value
// (also by one nanosecond, and a midnight of UTC that is not midnight in the location of the
// value). The error wraps ErrTimeValue and the encoder holds nothing.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDate_EncodeRefusals(t *testing.T) {
	zone := time.FixedZone(
		"",
		P9_OFFSET_0530,
	)

	_P9EncodeRefusals(
		t,
		_P9DateCodec(),
		[]*_P9EncodeRefusal[time.Time]{
			{
				name: "year_1581",
				value: time.Date(
					1581,
					12,
					31,
					0,
					0,
					0,
					0,
					time.UTC,
				),
			},
			{
				name: "year_10000",
				value: time.Date(
					10000,
					1,
					1,
					0,
					0,
					0,
					0,
					time.UTC,
				),
			},
			{
				name: "year_0",
				value: time.Date(
					0,
					1,
					1,
					0,
					0,
					0,
					0,
					time.UTC,
				),
			},
			{
				name: "year_negative",
				value: time.Date(
					-100,
					6,
					1,
					0,
					0,
					0,
					0,
					time.UTC,
				),
			},
			{
				name:  "zero_time",
				value: time.Time{},
			},
			{
				name: "one_second_after_midnight",
				value: time.Date(
					2020,
					1,
					1,
					0,
					0,
					1,
					0,
					time.UTC,
				),
			},
			{
				name: "one_nanosecond_after_midnight",
				value: time.Date(
					2020,
					1,
					1,
					0,
					0,
					0,
					1,
					time.UTC,
				),
			},
			{
				name: "noon",
				value: time.Date(
					2020,
					1,
					1,
					12,
					0,
					0,
					0,
					time.UTC,
				),
			},
			{
				name: "last_nanosecond_of_the_day",
				value: time.Date(
					2020,
					1,
					1,
					23,
					59,
					59,
					999999999,
					time.UTC,
				),
			},
			{
				name: "midnight_of_utc_is_not_midnight_in_the_zone",
				value: time.Date(
					2020,
					1,
					1,
					0,
					0,
					0,
					0,
					time.UTC,
				).In(zone),
			},
		},
	)
}
