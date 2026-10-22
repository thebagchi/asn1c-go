package per_test

import (
	"math"
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _P9TimeOfDayCodec is TIME-OF-DAY: Table 2 row 21, TIME-OF-DAY-ENCODING (X.691 32.3.7), the type
// of X.680 38.4.2 (Time=HMS, Local-or-UTC=L). A caller encodes the time since midnight as a
// time.Duration of 0 to 24 hours in whole seconds.
//
// Revisions:
//   - 2026-10-19 16:02: initial creation
func _P9TimeOfDayCodec() *_P9Codec[time.Duration] {
	seconds := func(
		t *testing.T,
		row *_P9Row,
	) time.Duration {
		t.Helper()

		return time.Duration(row.Seconds) * time.Second
	}

	return &_P9Codec[time.Duration]{
		name: "EncodeTimeOfDay",
		encode: func(
			enc *per.Encoder,
			value time.Duration,
		) error {
			return enc.EncodeTimeOfDay(value)
		},
		decode: func(dec *per.Decoder) (time.Duration, error) {
			return dec.DecodeTimeOfDay()
		},
		value: seconds,
		want:  seconds,
		same: func(
			t *testing.T,
			got,
			want time.Duration,
		) {
			t.Helper()

			if got != want {
				t.Fatalf(
					"decoded %v, want %v",
					got,
					want,
				)
			}
		},
		zero: func(value time.Duration) bool {
			return value == 0
		},
	}
}

// TestTimeOfDay_Vectors checks EncodeTimeOfDay and DecodeTimeOfDay against the octets of the
// oracles for TIME-OF-DAY-ENCODING (X.691 32.3.7): hours 0..24, minutes 0..59 and seconds 0..60,
// 5, 6 and 6 bits. 24:00:00 (86400 seconds) is the midnight at the end of the day, which X.680
// 38.4.2 allows (note) and the hours range 0..24 holds.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTimeOfDay_Vectors(t *testing.T) {
	_P9Vectors(
		t,
		_P9TimeOfDayCodec(),
		_P9Load(t).Tod,
	)
}

// TestTimeOfDay_Framed writes each TIME-OF-DAY between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTimeOfDay_Framed(t *testing.T) {
	_P9Framed(
		t,
		_P9TimeOfDayCodec(),
		_P9Load(t).Tod,
	)
}

// TestTimeOfDay_Truncated cuts each TIME-OF-DAY encoding short.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTimeOfDay_Truncated(t *testing.T) {
	_P9Truncated(
		t,
		_P9TimeOfDayCodec(),
		_P9Load(t).Tod,
	)
}

// TestTimeOfDay_DecodeRefusals decodes encodings of TIME-OF-DAY-ENCODING that no time.Duration
// of a day holds: hours 24 with minutes or seconds not zero (the hours range 0..24 is only for the
// end-of-day midnight), and seconds 60 (a leap second: a time.Duration cannot tell 23:59:60 from
// 24:00:00). The error wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTimeOfDay_DecodeRefusals(t *testing.T) {
	_P9DecodeRefusals(
		t,
		_P9TimeOfDayCodec(),
		_P9Load(t).RefuseTod,
	)
}

// TestTimeOfDay_EncodeRefusals checks the values that EncodeTimeOfDay refuses: a negative
// duration, one beyond 24 hours, and one with a part of a second (TIME-OF-DAY has no fraction:
// X.680 38.4.2 has Time=HMS). The error wraps ErrTimeValue and the encoder holds nothing.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTimeOfDay_EncodeRefusals(t *testing.T) {
	_P9EncodeRefusals(
		t,
		_P9TimeOfDayCodec(),
		[]*_P9EncodeRefusal[time.Duration]{
			{
				name:  "minus_one_nanosecond",
				value: -time.Nanosecond,
			},
			{
				name:  "minus_one_second",
				value: -time.Second,
			},
			{
				name:  "minus_24_hours",
				value: -24 * time.Hour,
			},
			{
				name:  "minimum",
				value: time.Duration(math.MinInt64),
			},
			{
				name:  "24_hours_and_one_nanosecond",
				value: 24*time.Hour + time.Nanosecond,
			},
			{
				name:  "24_hours_and_one_second",
				value: 24*time.Hour + time.Second,
			},
			{
				name:  "48_hours",
				value: 48 * time.Hour,
			},
			{
				name:  "maximum",
				value: time.Duration(math.MaxInt64),
			},
			{
				name:  "one_nanosecond",
				value: time.Nanosecond,
			},
			{
				name:  "half_a_second",
				value: 500 * time.Millisecond,
			},
			{
				name:  "one_second_and_one_nanosecond",
				value: time.Second + time.Nanosecond,
			},
			{
				name:  "last_nanosecond_of_the_day",
				value: 24*time.Hour - time.Nanosecond,
			},
			{
				name:  "ninety_minutes_and_one_millisecond",
				value: 90*time.Minute + time.Millisecond,
			},
		},
	)
}
