package per

import (
	"testing"
	"time"
)

// This file is an internal test because the harness reads the codec counts.

// _FuzzDay returns a UTC time of the given year, month and day, at the given hour, minute and
// second. It is the value that the seeds of the time fuzz functions write.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
func _FuzzDay(
	year int,
	month time.Month,
	day int,
	clock time.Duration,
) time.Time {
	return time.Date(
		year,
		month,
		day,
		0,
		0,
		0,
		0,
		time.UTC,
	).Add(clock)
}

// _SameTime reports whether two times are the same instant at the same offset from UTC. The
// time.Time of a decoder holds a zone pointer and a reading of the clock, which a deep
// comparison would read as a difference.
//
// Revisions:
//   - 2026-10-21 21:00: initial creation (review P30)
func _SameTime(
	first,
	second time.Time,
) bool {
	return first.Equal(second) && _Offset(first) == _Offset(second)
}

// _Offset returns the offset of a time from UTC, in seconds.
//
// Revisions:
//   - 2026-10-21 21:01: initial creation (review P30)
func _Offset(value time.Time) int {
	_, offset := value.Zone()

	return offset
}

// FuzzDecodeDate guards review P29-3 for DecodeDate.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeDate(f *testing.F) {
	pair := &_Pair[time.Time]{
		decode: (*Decoder).DecodeDate,
		encode: (*Encoder).EncodeDate,
		equal:  _SameTime,
	}

	for _, value := range []time.Time{
		_FuzzDay(
			2020,
			time.June,
			15,
			0,
		),
		_FuzzDay(
			1600,
			time.January,
			1,
			0,
		),
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}

// FuzzDecodeDateTime guards review P29-3 for DecodeDateTime.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeDateTime(f *testing.F) {
	pair := &_Pair[time.Time]{
		decode: (*Decoder).DecodeDateTime,
		encode: (*Encoder).EncodeDateTime,
		equal:  _SameTime,
	}

	for _, value := range []time.Time{
		_FuzzDay(
			2020,
			time.June,
			15,
			12*time.Hour+30*time.Minute+45*time.Second,
		),
		_FuzzDay(
			9999,
			time.December,
			31,
			23*time.Hour+59*time.Minute+59*time.Second,
		),
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}

// FuzzDecodeDuration guards review P29-3 for DecodeDuration.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeDuration(f *testing.F) {
	pair := &_Pair[time.Duration]{
		decode: (*Decoder).DecodeDuration,
		encode: (*Encoder).EncodeDuration,
	}

	for _, value := range []time.Duration{
		90 * time.Minute,
		1500 * time.Millisecond,
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}

// FuzzDecodeTimeOfDay guards review P29-3 for DecodeTimeOfDay.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeTimeOfDay(f *testing.F) {
	pair := &_Pair[time.Duration]{
		decode: (*Decoder).DecodeTimeOfDay,
		encode: (*Encoder).EncodeTimeOfDay,
	}

	for _, value := range []time.Duration{
		13*time.Hour + 5*time.Minute + 9*time.Second,
		0,
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}

// FuzzDecodeTime guards review P29-3 for DecodeTime. The seeds are a UTC time and a time in a
// zone of 5 hours 30 minutes with a fraction.
//
// Revisions:
//   - 2026-10-21 18:52: initial creation (review P29-3)
//   - 2026-10-21 21:00: the seeds come from _FuzzSeedValue, which checks each one (review P30)
func FuzzDecodeTime(f *testing.F) {
	var (
		zone = time.FixedZone(
			"fuzz",
			5*60*60+30*60,
		)
		pair = &_Pair[time.Time]{
			decode: (*Decoder).DecodeTime,
			encode: (*Encoder).EncodeTime,
			equal:  _SameTime,
		}
	)

	for _, value := range []time.Time{
		_FuzzDay(
			2020,
			time.June,
			15,
			12*time.Hour+30*time.Minute,
		),
		time.Date(
			2020,
			time.June,
			15,
			12,
			30,
			45,
			500000000,
			zone,
		),
	} {
		_FuzzSeedValue(
			f,
			nil,
			pair,
			value,
		)
	}

	f.Fuzz(
		func(
			t *testing.T,
			data []byte,
		) {
			_FuzzRoundTrip(
				t,
				data,
				pair,
			)
		},
	)
}
