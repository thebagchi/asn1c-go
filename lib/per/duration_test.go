package per_test

import (
	"math"
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// _P9DurationCodec is DURATION: Table 2 row 37, DURATION-INTERVAL-ENCODING (X.691 32.6.1), the
// type of X.680 38.4.4. A caller encodes a time.Duration; the elements are the hours, minutes and
// seconds of it, and the fraction of a second.
//
// What the rows hold (a time.Duration has no accuracy, so the tester chose the abstract value
// that has the fewest elements, by X.680 38.2.3 and X.691 32.6.3):
//   - an element that is not zero is present; the least significant element is present also when
//     it is zero; the seconds are the least significant element when there is a fraction of a
//     second, or when the value is zero (the duration 0 is PT0S); an element that is zero and not
//     the least significant is absent (32.6.3);
//   - the fractional-part is the fraction of the seconds, with the fewest digits (1.500 s is
//     number-of-digits 1, value 5: 32.6.5 lets a decoder recover trailing zeros, a time.Duration
//     does not keep them);
//   - years, months, weeks and days are never written.
//
// Revisions:
//   - 2026-10-19 16:02: initial creation
func _P9DurationCodec() *_P9Codec[time.Duration] {
	nanos := func(
		t *testing.T,
		row *_P9Row,
	) time.Duration {
		t.Helper()

		return time.Duration(row.Nanos)
	}

	return &_P9Codec[time.Duration]{
		name: "EncodeDuration",
		encode: func(
			enc *per.Encoder,
			value time.Duration,
		) error {
			return enc.EncodeDuration(value)
		},
		decode: func(dec *per.Decoder) (time.Duration, error) {
			return dec.DecodeDuration()
		},
		value: nanos,
		want:  nanos,
		same: func(
			t *testing.T,
			got,
			want time.Duration,
		) {
			t.Helper()

			if got != want {
				t.Fatalf(
					"decoded %v (%d ns), want %v (%d ns)",
					got,
					int64(got),
					want,
					int64(want),
				)
			}
		},
		zero: func(value time.Duration) bool {
			return value == 0
		},
	}
}

// TestDuration_Vectors checks EncodeDuration and DecodeDuration against the octets of the
// oracles for DURATION-INTERVAL-ENCODING (X.691 32.6.1): an 8-bit preamble for the optional
// elements, then each present element as an integer with an extension marker (5, 4, 6, 5, 5, 6, 6
// bits in the root, so that 25 hours is a root value and 1000 hours is an extension value), then
// the fractional-part with number-of-digits 1..3 in the root and the value 0..999 in the root. The
// rows hold 0, 1 ns, fractions of 1 to 9 digits alone and after seconds, minutes and hours,
// 59m59s, 25h, 1000h and the largest time.Duration.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDuration_Vectors(t *testing.T) {
	_P9Vectors(
		t,
		_P9DurationCodec(),
		_P9Load(t).Dur,
	)
}

// TestDuration_Framed writes each DURATION between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDuration_Framed(t *testing.T) {
	_P9Framed(
		t,
		_P9DurationCodec(),
		_P9Load(t).Dur,
	)
}

// TestDuration_Truncated cuts each DURATION encoding short.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDuration_Truncated(t *testing.T) {
	_P9Truncated(
		t,
		_P9DurationCodec(),
		_P9Load(t).Dur,
	)
}

// TestDuration_DecodeRefusals decodes encodings of DURATION-INTERVAL-ENCODING that a
// time.Duration cannot hold: years, months, weeks and days (X.680 38.2.4: there is no agreed
// length of a month or a year, and a day or a week is a calendar unit, not 24 or 168 hours: the
// decoder does not guess), no element at all (X.680 38.2.3 wants at least one), a total beyond
// the largest time.Duration, a fraction value that does not fit its digits (value 10 with 1
// digit), and a fraction that is not a whole number of nanoseconds (the fraction is of the least
// significant element, 32.6.4, so hours with 13 digits are fractions of a nanosecond). The
// error wraps ErrTimeValue.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDuration_DecodeRefusals(t *testing.T) {
	_P9DecodeRefusals(
		t,
		_P9DurationCodec(),
		_P9Load(t).RefuseDur,
	)
}

// TestDuration_EncodeRefusals checks that EncodeDuration refuses a negative duration (X.680
// 38.3.6: the designations are digits, with no sign). The error wraps ErrTimeValue and the
// encoder holds nothing.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestDuration_EncodeRefusals(t *testing.T) {
	_P9EncodeRefusals(
		t,
		_P9DurationCodec(),
		[]*_P9EncodeRefusal[time.Duration]{
			{
				name:  "minus_one_nanosecond",
				value: -time.Nanosecond,
			},
			{
				name:  "minus_one_hour",
				value: -time.Hour,
			},
			{
				name:  "minimum",
				value: time.Duration(math.MinInt64),
			},
		},
	)
}
