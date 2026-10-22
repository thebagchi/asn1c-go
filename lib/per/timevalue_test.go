package per_test

import (
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _P9TimeCodec is the unconstrained TIME: MIXED-ENCODING (X.691 32.1.4 note 2, 32.11.5), the
// alternative row-33, DATE-TIME-ENCODING {DATE-TYPE, TIME-TYPE}. A caller encodes a time.Time:
//   - date: row-7 (DATE-ENCODING) when the year is 0..9999 (X.680 38.2.1: Year=Basic 1582..9999
//     and Year=Proleptic 0..1581; X.691 Table 2 row 7 holds both), row-8 (ANY-DATE-ENCODING)
//     for the other years (Negative or Large);
//   - time: TIME-TYPE (32.11.8) with row-22 (TIME-OF-DAY-UTC-ENCODING) when the location is
//     time.UTC, row-23 (TIME-OF-DAY-AND-DIFF-ENCODING) for any other location, also with an
//     offset of zero (Local-or-UTC=Z and LD are different abstract values, and X.680 38.2.1 says
//     the difference is positive when the local time is ahead of or equal to UTC); the clock is
//     the wall clock of the value in its own location, and the difference is its offset;
//   - the nanoseconds, when not zero: row-31 or row-32 (the FRACTION variants) with
//     number-of-digits in TIME-TYPE (32.11.9) = the fewest digits (9 minus the trailing zeros of
//     the nanoseconds), and fraction = the nanoseconds divided by 10 to the power of 9 minus the
//     digits (32.3.17).
//
// The decoder gives time.UTC for the rows 22 and 31, and a fixed zone of the offset (not
// time.UTC, also for an offset of zero) for the rows 23 and 32. A decoded value is the same
// instant as the written one, with the same offset, and it is in time.UTC if and only if the
// original was.
//
// Revisions:
//   - 2026-10-19 16:02: initial creation
func _P9TimeCodec() *_P9Codec[time.Time] {
	clock := func(
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
	}

	return &_P9Codec[time.Time]{
		name: "EncodeTime",
		encode: func(
			enc *per.Encoder,
			value time.Time,
		) error {
			return enc.EncodeTime(value)
		},
		decode: func(dec *per.Decoder) (time.Time, error) {
			return dec.DecodeTime()
		},
		value: clock,
		want:  clock,
		same:  _P9Same,
		zero:  time.Time.IsZero,
	}
}

// TestTime_Vectors checks EncodeTime and DecodeTime against the octets of the oracles for
// MIXED-ENCODING (X.691 32.11): the 6-bit index of the alternative (53 alternatives, no extension
// marker), then DATE-TIME-ENCODING {DATE-TYPE, TIME-TYPE}. The rows hold the years -292277022000
// to 292277026595 with edges at 0, 1, 1581, 1582, 1749, 2004, 2005, 2020, 2021, 2276, 2277, 9999
// and 10000, leap days, 17 zones (+00:00 among them) with and without a fraction, fractions of
// 1 to 9 digits, the trailing zeros that are left out, the edges of the day, and (decode only)
// fractions that carry trailing zeros, which a time.Time cannot keep.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTime_Vectors(t *testing.T) {
	_P9Vectors(
		t,
		_P9TimeCodec(),
		_P9Load(t).Time,
	)
}

// TestTime_Framed writes each TIME between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTime_Framed(t *testing.T) {
	_P9Framed(
		t,
		_P9TimeCodec(),
		_P9Load(t).Time,
	)
}

// TestTime_Truncated cuts each TIME encoding short.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTime_Truncated(t *testing.T) {
	_P9Truncated(
		t,
		_P9TimeCodec(),
		_P9Load(t).Time,
	)
}

// TestTime_DecodeRefusals decodes encodings of MIXED-ENCODING that DecodeTime does not take, each
// with its reason in the name: a row that a time.Time cannot hold (the local time without an
// offset of rows 21 and 30, the hours-only and minutes-only rows, a date of the rows 1 and 3, a
// date or a time alone, a duration); a fraction of more than 9 digits or a value that does not
// fit its digits; a day that its month does not have; hours 24 and seconds 60; a time difference
// of -00:00 or beyond 15 hours (X.680 38.2.1: -15 to +15 hours); and a year that is not in the
// range of its row (row-7: 0..9999, row-8: the other years). The error wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTime_DecodeRefusals(t *testing.T) {
	_P9DecodeRefusals(
		t,
		_P9TimeCodec(),
		_P9Load(t).RefuseTime,
	)
}

// TestTime_ZoneIdentity checks that the zone is its offset and its being time.UTC, and not its
// name: a fixed zone called "UTC" or "GMT" with an offset of zero is not time.UTC, so it is sent
// as row-23 with the difference +00:00, as the +00:00 rows say; a fixed zone with a name and one
// without give the same octets; the wall clock of the value in its location is what is sent.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTime_ZoneIdentity(t *testing.T) {
	cases := []struct {
		name string
		zone *time.Location
		same *time.Location
	}{
		{
			name: "utc_named_zone_is_not_utc",
			zone: time.FixedZone(
				"UTC",
				0,
			),
			same: time.FixedZone(
				"",
				0,
			),
		},
		{
			name: "gmt",
			zone: time.FixedZone(
				"GMT",
				0,
			),
			same: time.FixedZone(
				"",
				0,
			),
		},
		{
			name: "named_offset",
			zone: time.FixedZone(
				"IST",
				P9_OFFSET_0530,
			),
			same: time.FixedZone(
				"",
				P9_OFFSET_0530,
			),
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					encode := func(zone *time.Location) []byte {
						enc := ENCODERS[aligned]()

						if err := enc.EncodeTime(time.Date(
							2020,
							12,
							31,
							12,
							34,
							56,
							500000000,
							zone,
						)); err != nil {
							t.Fatalf(
								"EncodeTime = %v",
								err,
							)
						}

						return enc.Bytes()
					}

					_Compare(
						t,
						encode(tc.zone),
						encode(tc.same),
					)

					utc := encode(time.UTC)
					if string(utc) == string(encode(tc.zone)) {
						t.Fatalf(
							"zone %v and UTC give % x",
							tc.zone,
							utc,
						)
					}
				},
			)
		}
	}
}

// TestTime_EncodeRefusals checks the values that EncodeTime refuses: an offset that is not whole
// minutes (TIME-DIFFERENCE has hours and minutes only: 32.3.3), and an offset more than 15
// hours from UTC (X.680 38.2.1; the +15:00 and -15:00 rows are values). The error wraps
// ErrTimeValue and the encoder holds nothing.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestTime_EncodeRefusals(t *testing.T) {
	zoned := func(seconds int) time.Time {
		return time.Date(
			2020,
			12,
			31,
			12,
			34,
			56,
			0,
			time.FixedZone(
				"",
				seconds,
			),
		)
	}

	_P9EncodeRefusals(
		t,
		_P9TimeCodec(),
		[]*_P9EncodeRefusal[time.Time]{
			{
				name:  "offset_plus_one_second",
				value: zoned(1),
			},
			{
				name:  "offset_minus_30_seconds",
				value: zoned(-30),
			},
			{
				name:  "offset_0530_and_15_seconds",
				value: zoned(P9_OFFSET_0530 + 15),
			},
			{
				name:  "offset_minus_0530_and_15_seconds",
				value: zoned(-P9_OFFSET_0530 - 15),
			},
			{
				name:  "offset_plus_1501",
				value: zoned(15*3600 + 60),
			},
			{
				name:  "offset_minus_1501",
				value: zoned(-15*3600 - 60),
			},
			{
				name:  "offset_plus_1530",
				value: zoned(15*3600 + 30*60),
			},
			{
				name:  "offset_plus_1600",
				value: zoned(16 * 3600),
			},
			{
				name:  "offset_minus_1600",
				value: zoned(-16 * 3600),
			},
			{
				name:  "offset_plus_24_hours",
				value: zoned(24 * 3600),
			},
		},
	)
}
