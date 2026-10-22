package per_test

import (
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _P9DateTimeCodec is DATE-TIME: Table 2 row 33 with the date of row 7 and the time of row 21,
// DATE-TIME-ENCODING {DATE-ENCODING, TIME-OF-DAY-ENCODING} (X.691 32.4.1, 32.4.2), the type of
// X.680 38.4.3 (Date=YMD, Year=Basic, Time=HMS, Local-or-UTC=L). A caller encodes the wall clock
// of the time.Time in its own location, with whole seconds. The type has no offset (L), so the
// decoder gives the wall clock in time.UTC.
//
// Revisions:
//   - 2026-10-19 16:02: initial creation
func _P9DateTimeCodec() *_P9Codec[time.Time] {
	return &_P9Codec[time.Time]{
		name: "EncodeDateTime",
		encode: func(
			enc *per.Encoder,
			value time.Time,
		) error {
			return enc.EncodeDateTime(value)
		},
		decode: func(dec *per.Decoder) (time.Time, error) {
			return dec.DecodeDateTime()
		},
		value: func(
			t *testing.T,
			row *_P9Row,
		) time.Time {
			t.Helper()

			return _P9Clock(
				t,
				row,
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

			return _P9Clock(
				t,
				row,
				time.UTC,
			)
		},
		same: _P9Wall,
		zero: time.Time.IsZero,
	}
}

// TestDateTime_Vectors checks EncodeDateTime and DecodeDateTime against the octets of the
// oracles: the encoding of DATE-ENCODING followed by that of TIME-OF-DAY-ENCODING, with no
// preamble (X.691 32.4.1: a SEQUENCE of two components). The rows include one wall clock in six
// zones: the wall clock is what is sent, not the instant.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDateTime_Vectors(t *testing.T) {
	_P9Vectors(
		t,
		_P9DateTimeCodec(),
		_P9Load(t).Dt,
	)
}

// TestDateTime_Framed writes each DATE-TIME between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDateTime_Framed(t *testing.T) {
	_P9Framed(
		t,
		_P9DateTimeCodec(),
		_P9Load(t).Dt,
	)
}

// TestDateTime_Truncated cuts each DATE-TIME encoding short.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDateTime_Truncated(t *testing.T) {
	_P9Truncated(
		t,
		_P9DateTimeCodec(),
		_P9Load(t).Dt,
	)
}

// TestDateTime_DecodeRefusals decodes encodings that are not values of a time.Time: hours 24
// (the end-of-day midnight is the same instant as 00:00:00 of the next day, and a time.Time keeps
// no end-of-day property), seconds 60, a day that the month does not have, and a year outside
// 1582..9999 (Year=Basic). The error wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDateTime_DecodeRefusals(t *testing.T) {
	_P9DecodeRefusals(
		t,
		_P9DateTimeCodec(),
		_P9Load(t).RefuseDt,
	)
}

// TestDateTime_EncodeRefusals checks the values that EncodeDateTime refuses: a part of a second
// (Time=HMS has no fraction) and a year outside 1582..9999 (also the zero time.Time). The error
// wraps ErrTimeValue and the encoder holds nothing.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDateTime_EncodeRefusals(t *testing.T) {
	clock := func(
		year,
		hour,
		second,
		nanos int,
	) time.Time {
		return time.Date(
			year,
			6,
			15,
			hour,
			0,
			second,
			nanos,
			time.UTC,
		)
	}

	_P9EncodeRefusals(
		t,
		_P9DateTimeCodec(),
		[]*_P9EncodeRefusal[time.Time]{
			{
				name: "one_nanosecond",
				value: clock(
					2020,
					0,
					0,
					1,
				),
			},
			{
				name: "half_a_second",
				value: clock(
					2020,
					12,
					30,
					500000000,
				),
			},
			{
				name: "last_nanosecond",
				value: clock(
					2020,
					23,
					59,
					999999999,
				),
			},
			{
				name: "year_1581",
				value: clock(
					1581,
					12,
					0,
					0,
				),
			},
			{
				name: "year_10000",
				value: clock(
					10000,
					12,
					0,
					0,
				),
			},
			{
				name: "year_0",
				value: clock(
					0,
					12,
					0,
					0,
				),
			},
			{
				name: "year_negative",
				value: clock(
					-5,
					12,
					0,
					0,
				),
			},
			{
				name:  "zero_time",
				value: time.Time{},
			},
			{
				name: "last_second_before_1582",
				value: time.Date(
					1581,
					12,
					31,
					23,
					59,
					59,
					0,
					time.UTC,
				),
			},
		},
	)
}
