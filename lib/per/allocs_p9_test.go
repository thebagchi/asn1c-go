package per_test

import (
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// ALLOC_P9_ENCODE_MAX and ALLOC_P9_DECODE_MAX are what the codecs of phase 9 may allocate beyond
// the coder itself: none, as the plan says of the codecs. The value is built before the
// measurement, as generated code holds it. ALLOC_P9_ZONE_MAX is for DecodeTime of a value with an
// offset: time.FixedZone makes a *time.Location (3 allocations, measured), which is the only
// allocation the decoder may make, and only for a row-23 or row-32 value.
const (
	ALLOC_P9_ENCODE_MAX = 0
	ALLOC_P9_DECODE_MAX = 0
	ALLOC_P9_ZONE_MAX   = 3
)

// P9_ALLOC_CLOCK and P9_ALLOC_SPAN are the values of the TIME-OF-DAY and DURATION cases: 12:34:56
// and 25 hours 59 minutes 1.234 milliseconds.
const (
	P9_ALLOC_CLOCK = 12*time.Hour + 34*time.Minute + 56*time.Second
	P9_ALLOC_SPAN  = 25*time.Hour + 59*time.Minute + 1234*time.Microsecond
)

// _P9AllocCase is one codec of this phase. write encodes a fixed value on an encoder after a
// BOOLEAN; read decodes it from a decoder after the BOOLEAN. max is the number of allocations
// that the decoder may make.
type _P9AllocCase struct {
	name  string
	write func(enc *per.Encoder) error
	read  func(dec *per.Decoder) error
	max   float64
}

// _P9AllocCases builds the cases: each of the five codecs, and DecodeTime of a UTC value with a
// fraction (row 31) and of one with an offset (rows 23 and 32).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9AllocCases() []*_P9AllocCase {
	var (
		zone = time.FixedZone(
			"",
			P9_OFFSET_0530,
		)
		day = time.Date(
			2020,
			12,
			31,
			0,
			0,
			0,
			0,
			time.UTC,
		)
		clock = time.Date(
			2020,
			12,
			31,
			12,
			34,
			56,
			0,
			time.UTC,
		)
		fraction = clock.Add(123456789 * time.Nanosecond)
		zoned    = time.Date(
			2020,
			12,
			31,
			12,
			34,
			56,
			0,
			zone,
		)
		zonedFraction = zoned.Add(500 * time.Millisecond)
	)

	return []*_P9AllocCase{
		{
			name: "Date",
			write: func(enc *per.Encoder) error {
				return enc.EncodeDate(day)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeDate()

				return err
			},
			max: ALLOC_P9_DECODE_MAX,
		},
		{
			name: "TimeOfDay",
			write: func(enc *per.Encoder) error {
				return enc.EncodeTimeOfDay(P9_ALLOC_CLOCK)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeTimeOfDay()

				return err
			},
			max: ALLOC_P9_DECODE_MAX,
		},
		{
			name: "DateTime",
			write: func(enc *per.Encoder) error {
				return enc.EncodeDateTime(zoned)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeDateTime()

				return err
			},
			max: ALLOC_P9_DECODE_MAX,
		},
		{
			name: "Duration",
			write: func(enc *per.Encoder) error {
				return enc.EncodeDuration(P9_ALLOC_SPAN)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeDuration()

				return err
			},
			max: ALLOC_P9_DECODE_MAX,
		},
		{
			name: "Time_utc",
			write: func(enc *per.Encoder) error {
				return enc.EncodeTime(clock)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeTime()

				return err
			},
			max: ALLOC_P9_DECODE_MAX,
		},
		{
			name: "Time_utc_fraction",
			write: func(enc *per.Encoder) error {
				return enc.EncodeTime(fraction)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeTime()

				return err
			},
			max: ALLOC_P9_DECODE_MAX,
		},
		{
			name: "Time_offset",
			write: func(enc *per.Encoder) error {
				return enc.EncodeTime(zoned)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeTime()

				return err
			},
			max: ALLOC_P9_ZONE_MAX,
		},
		{
			name: "Time_offset_fraction",
			write: func(enc *per.Encoder) error {
				return enc.EncodeTime(zonedFraction)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeTime()

				return err
			},
			max: ALLOC_P9_ZONE_MAX,
		},
	}
}

// TestAllocs_P9Encode checks that no encoder of the time types allocates beyond the encoder
// itself. The measurement subtracts an encoder that writes only the first BOOLEAN. The error of
// a stub counts as no allocation, so the encode must also succeed (the first call checks it).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestAllocs_P9Encode(t *testing.T) {
	for _, tc := range _P9AllocCases() {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"_"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					enc := ENCODERS[aligned]()

					if err := enc.EncodeBoolean(true); err != nil {
						t.Fatalf(
							"EncodeBoolean = %v",
							err,
						)
					}

					if err := tc.write(enc); err != nil {
						t.Fatalf(
							"write = %v",
							err,
						)
					}

					var (
						base = testing.AllocsPerRun(
							ALLOC_RUNS,
							func() {
								enc := ENCODERS[aligned]()
								_ = enc.EncodeBoolean(true)
							},
						)
						total = testing.AllocsPerRun(
							ALLOC_RUNS,
							func() {
								enc := ENCODERS[aligned]()
								_ = enc.EncodeBoolean(true)
								_ = tc.write(enc)
							},
						)
					)

					t.Logf(
						"encode: %.0f allocations beyond the BOOLEAN",
						total-base,
					)

					if got := total - base; got > ALLOC_P9_ENCODE_MAX {
						t.Errorf(
							"encode: %.0f allocations, max %d",
							got,
							ALLOC_P9_ENCODE_MAX,
						)
					}
				},
			)
		}
	}
}

// TestAllocs_P9Decode checks that no decoder of the time types allocates beyond the decoder
// itself, except the zone of DecodeTime for an offset (ALLOC_P9_ZONE_MAX).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func TestAllocs_P9Decode(t *testing.T) {
	for _, tc := range _P9AllocCases() {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"_"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					enc := ENCODERS[aligned]()

					if err := enc.EncodeBoolean(true); err != nil {
						t.Fatalf(
							"EncodeBoolean = %v",
							err,
						)
					}

					if err := tc.write(enc); err != nil {
						t.Fatalf(
							"write = %v",
							err,
						)
					}

					var (
						data = enc.Bytes()

						dec = DECODERS[aligned](data)
					)

					if _, err := dec.DecodeBoolean(); err != nil {
						t.Fatalf(
							"DecodeBoolean = %v",
							err,
						)
					}

					if err := tc.read(dec); err != nil {
						t.Fatalf(
							"read = %v",
							err,
						)
					}

					var (
						base = testing.AllocsPerRun(
							ALLOC_RUNS,
							func() {
								dec := DECODERS[aligned](data)
								_, _ = dec.DecodeBoolean()
							},
						)
						total = testing.AllocsPerRun(
							ALLOC_RUNS,
							func() {
								dec := DECODERS[aligned](data)
								_, _ = dec.DecodeBoolean()
								_ = tc.read(dec)
							},
						)
					)

					t.Logf(
						"decode: %.0f allocations beyond the BOOLEAN",
						total-base,
					)

					if got := total - base; got > tc.max {
						t.Errorf(
							"decode: %.0f allocations, max %.0f",
							got,
							tc.max,
						)
					}
				},
			)
		}
	}
}
