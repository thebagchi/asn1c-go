package per_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_TIMES is the kind key in testing.json of testing/times.py, which asks pycrate 0.8.1 and
// Erlang/OTP 29.1.1
// (testing.asn1, the text of specs/builtin.asn1) for the encoding of each value. Neither
// oracle knows the time types, so the expected octets are the answers for the type that X.691
// 32.1.2 names in column 3 of Table 2, and for MIXED-ENCODING (32.11.5) in place of the
// unconstrained TIME (32.1.4 note 2). The two oracles agree on every row (the file says so
// per row, and the "native" record says what each does with the time types themselves).
//
//	DATE        row 7, DATE-ENCODING (32.2.7)
//	TIME-OF-DAY row 21, TIME-OF-DAY-ENCODING (32.3.7)
//	DATE-TIME   row 33 with rows 7 and 21 (32.4.1, 32.4.2)
//	DURATION    row 37, DURATION-INTERVAL-ENCODING (32.6.1)
//	TIME        MIXED-ENCODING row 33, DATE-TYPE, TIME-TYPE (32.11)
const (
	VECTOR_TIMES = "times"
)

// The kinds of row of testing.json (times).
const (
	P9_DATE = "date"
	P9_TOD  = "tod"
	P9_DT   = "dt"
	P9_DUR  = "dur"
	P9_TIME = "time"
)

// P9_CYCLE_YEARS years of the Gregorian calendar are exactly P9_CYCLE_DAYS days, of
// P9_DAY_SECONDS each.
const (
	P9_CYCLE_YEARS = 400
	P9_CYCLE_DAYS  = 146097
	P9_DAY_SECONDS = 86400
)

// P9_OFFSET_0530 is the offset +05:30 in seconds.
const (
	P9_OFFSET_0530 = 5*3600 + 30*60
)

// P9_UTC is the zone text of time.UTC in the rows; P9_PER_MINUTE is the seconds in a minute and
// the minutes in an hour.
const (
	P9_UTC        = "UTC"
	P9_PER_MINUTE = 60
)

type _P9Row struct {
	Kind       string   `json:"kind"`
	Year       int64    `json:"year"`
	Month      int      `json:"month"`
	Day        int      `json:"day"`
	Hour       int      `json:"hour"`
	Minute     int      `json:"minute"`
	Second     int      `json:"second"`
	Nanos      int64    `json:"ns"`
	Zone       string   `json:"zone"`
	Seconds    int64    `json:"seconds"`
	DecodeOnly bool     `json:"decode_only"`
	Why        string   `json:"why"`
	Probe      string   `json:"probe"`
	Oracles    []string `json:"oracles"`
	Agree      bool     `json:"agree"`
	Clause     string   `json:"clause"`
	Aper       string   `json:"aper"`
	Uper       string   `json:"uper"`
}

type _P9File struct {
	Date       []*_P9Row `json:"date"`
	Tod        []*_P9Row `json:"tod"`
	Dt         []*_P9Row `json:"dt"`
	Dur        []*_P9Row `json:"dur"`
	Time       []*_P9Row `json:"time"`
	RefuseDate []*_P9Row `json:"refuse_date"`
	RefuseTod  []*_P9Row `json:"refuse_tod"`
	RefuseDt   []*_P9Row `json:"refuse_dt"`
	RefuseDur  []*_P9Row `json:"refuse_dur"`
	RefuseTime []*_P9Row `json:"refuse_time"`
}

// _P9Load reads testing.json (times).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Load(t *testing.T) *_P9File {
	t.Helper()

	var file _P9File

	_Load(
		t,
		VECTOR_TIMES,
		&file,
	)

	return &file
}

// _P9Zone makes the location of a row: time.UTC for "UTC" or no text, and for "+HH:MM" or
// "-HH:MM" a fixed zone of that offset (the zone "+00:00" is a zone that is not time.UTC).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Zone(
	t *testing.T,
	text string,
) *time.Location {
	t.Helper()

	if text == "" || text == P9_UTC {
		return time.UTC
	}

	var hours, minutes int

	if _, err := fmt.Sscanf(
		text[1:],
		"%d:%d",
		&hours,
		&minutes,
	); err != nil {
		t.Fatalf(
			"zone %q: %v",
			text,
			err,
		)
	}

	seconds := (hours*P9_PER_MINUTE + minutes) * P9_PER_MINUTE
	if text[0] == '-' {
		seconds = -seconds
	}

	return time.FixedZone(
		"",
		seconds,
	)
}

// _P9Clock makes the time.Time that a row describes, in the location of its zone. A year past
// the platform int (a 32-bit platform) does not go into time.Date: the Gregorian calendar
// repeats every P9_CYCLE_YEARS years, which are P9_CYCLE_DAYS days, so the same day in a year
// that fits is moved by whole cycles of Unix seconds. That is an oracle apart from the code
// under test, which counts the days itself.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
//   - 2026-10-21 21:52: a year past the platform int goes through whole 400-year cycles
//     (review P31)
func _P9Clock(
	t *testing.T,
	row *_P9Row,
	location *time.Location,
) time.Time {
	t.Helper()

	var (
		cycles = row.Year / P9_CYCLE_YEARS
		year   = row.Year - cycles*P9_CYCLE_YEARS
	)

	if int64(int(row.Year)) == row.Year {
		cycles = 0
		year = row.Year
	}

	near := time.Date(
		int(year),
		time.Month(row.Month),
		row.Day,
		row.Hour,
		row.Minute,
		row.Second,
		int(row.Nanos),
		location,
	)

	return time.Unix(
		near.Unix()+cycles*P9_CYCLE_DAYS*P9_DAY_SECONDS,
		int64(near.Nanosecond()),
	).In(location)
}

// _P9Name names a row for t.Run.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Name(
	row *_P9Row,
	index int,
) string {
	var text string

	switch row.Kind {
	case P9_DATE:
		text = fmt.Sprintf(
			"%d-%02d-%02d_%s",
			row.Year,
			row.Month,
			row.Day,
			row.Zone,
		)
	case P9_TOD:
		text = fmt.Sprintf(
			"%ds",
			row.Seconds,
		)
	case P9_DT, P9_TIME:
		text = fmt.Sprintf(
			"%d-%02d-%02dT%02d:%02d:%02d.%09d_%s",
			row.Year,
			row.Month,
			row.Day,
			row.Hour,
			row.Minute,
			row.Second,
			row.Nanos,
			row.Zone,
		)
	case P9_DUR:
		text = fmt.Sprintf(
			"%dns",
			row.Nanos,
		)
	default:
		text = row.Why
	}

	return fmt.Sprintf(
		"%d_%s",
		index,
		text,
	)
}

// _P9NoWrite checks that a refused encode left the encoder as it was: a BOOLEAN written after
// the refusal is the only content. The checks come before the first write.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9NoWrite(
	t *testing.T,
	enc *per.Encoder,
) {
	t.Helper()

	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatalf(
			"EncodeBoolean = %v",
			err,
		)
	}

	_Compare(
		t,
		enc.Bytes(),
		[]byte{0x80},
	)
}

// _P9Codec is one time type: how to encode a value, decode it, and tell whether two values are
// the same. value is what a caller encodes for a row; want is what the decoder returns for the
// row (the decoded value differs from the encoded one where the type has no offset: DATE and
// DATE-TIME give the wall clock in time.UTC).
type _P9Codec[T any] struct {
	name   string
	encode func(
		enc *per.Encoder,
		value T,
	) error
	decode func(dec *per.Decoder) (T, error)
	value  func(
		t *testing.T,
		row *_P9Row,
	) T
	want func(
		t *testing.T,
		row *_P9Row,
	) T
	same func(
		t *testing.T,
		got,
		want T,
	)
	zero func(value T) bool
}

// _P9Vectors encodes the value of each row and compares the octets with the oracles, then
// decodes them and compares the value with what the row says. A decode-only row (a spelling
// that a time.Time cannot keep, such as a trailing zero of a fraction) is decoded only.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Vectors[T any](
	t *testing.T,
	codec *_P9Codec[T],
	rows []*_P9Row,
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for index, row := range rows {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P9Name(
					row,
					index,
				),
				func(t *testing.T) {
					octets := _P9Octets(
						t,
						row,
						aligned,
					)

					if !row.DecodeOnly {
						enc := ENCODERS[aligned]()

						if err := codec.encode(
							enc,
							codec.value(
								t,
								row,
							),
						); err != nil {
							t.Fatalf(
								"%s = %v",
								codec.name,
								err,
							)
						}

						_Compare(
							t,
							enc.Bytes(),
							octets,
						)
					}

					var (
						dec = DECODERS[aligned](octets)

						got, err = codec.decode(dec)
					)
					if err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					codec.same(
						t,
						got,
						codec.want(
							t,
							row,
						),
					)
				},
			)
		}
	}
}

// _P9Framed writes each value between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Framed[T any](
	t *testing.T,
	codec *_P9Codec[T],
	rows []*_P9Row,
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for index, row := range rows {
			if row.DecodeOnly {
				continue
			}

			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P9Name(
					row,
					index,
				),
				func(t *testing.T) {
					value := codec.value(
						t,
						row,
					)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return codec.encode(
								enc,
								value,
							)
						},
						func(dec *per.Decoder) error {
							got, err := codec.decode(dec)
							if err != nil {
								return err
							}

							codec.same(
								t,
								got,
								codec.want(
									t,
									row,
								),
							)

							return nil
						},
					)
				},
			)
		}
	}
}

// _P9DecodeRefusals decodes the octets of each refusal row: the decoder must return an error
// that wraps ErrTimeValue and the zero value, in both variants. The octets are the encodings
// of the associated type, so the decoder reaches the value check, not the end of the data.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9DecodeRefusals[T any](
	t *testing.T,
	codec *_P9Codec[T],
	rows []*_P9Row,
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for index, row := range rows {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P9Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						dec = DECODERS[aligned](_P9Octets(
							t,
							row,
							aligned,
						))

						got, err = codec.decode(dec)
					)
					if !errors.Is(
						err,
						per.ErrTimeValue,
					) {
						t.Fatalf(
							"decode = %v, %v, want ErrTimeValue (%s)",
							got,
							err,
							row.Why,
						)
					}

					if !codec.zero(got) {
						t.Fatalf(
							"decode returned %v, want zero",
							got,
						)
					}
				},
			)
		}
	}
}

// _P9Truncated checks that the whole encoding decodes, then cuts it at every octet short of its
// length: the decoder must return an error and the zero value, and must not read bits that are
// not there.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Truncated[T any](
	t *testing.T,
	codec *_P9Codec[T],
	rows []*_P9Row,
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for index, row := range rows {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P9Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						octets = _P9Octets(
							t,
							row,
							aligned,
						)

						whole = DECODERS[aligned](octets)
					)
					if _, err := codec.decode(whole); err != nil {
						t.Fatalf(
							"decode of the whole encoding = %v",
							err,
						)
					}

					for cut := range len(octets) {
						var (
							dec = DECODERS[aligned](octets[:cut])

							got, err = codec.decode(dec)
						)
						if err == nil {
							t.Fatalf(
								"cut %d of %d = %v, want error",
								cut,
								len(octets),
								got,
							)
						}

						if !codec.zero(got) {
							t.Fatalf(
								"cut %d returned %v, want zero",
								cut,
								got,
							)
						}
					}
				},
			)
		}
	}
}

// _P9EncodeRefusal is one value that an encoder must refuse.
type _P9EncodeRefusal[T any] struct {
	name  string
	value T
}

// _P9EncodeRefusals runs the encoder on each value: the error must wrap ErrTimeValue, and the
// encoder must hold nothing.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9EncodeRefusals[T any](
	t *testing.T,
	codec *_P9Codec[T],
	cases []*_P9EncodeRefusal[T],
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					var (
						enc = ENCODERS[aligned]()

						err = codec.encode(
							enc,
							tc.value,
						)
					)
					if !errors.Is(
						err,
						per.ErrTimeValue,
					) {
						t.Fatalf(
							"%s(%v) = %v, want ErrTimeValue",
							codec.name,
							tc.value,
							err,
						)
					}

					_P9NoWrite(
						t,
						enc,
					)
				},
			)
		}
	}
}

// _P9Octets returns the expected octets of a row for a variant.
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Octets(
	t *testing.T,
	row *_P9Row,
	aligned bool,
) []byte {
	t.Helper()

	return _Unhex(
		t,
		map[bool]string{
			true:  row.Aper,
			false: row.Uper,
		}[aligned],
	)
}

// _P9Wall reports a decoded time that is not the wall clock of want in time.UTC. DATE and
// DATE-TIME carry no offset, so the decoder gives the clock in time.UTC (the choice is stated
// at DecodeDate and DecodeDateTime).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Wall(
	t *testing.T,
	got,
	want time.Time,
) {
	t.Helper()

	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf(
			"decoded %s in %v, want %s in UTC",
			got.Format(time.RFC3339Nano),
			got.Location(),
			want.Format(time.RFC3339Nano),
		)
	}
}

// _P9ZoneKind says how a time is zoned: time.UTC, or a fixed offset in seconds.
//
// Revisions:
//   - 2026-10-19 16:02: initial creation
func _P9ZoneKind(value time.Time) string {
	_, offset := value.Zone()

	if value.Location() == time.UTC {
		return P9_UTC
	}

	return fmt.Sprintf(
		"%+ds",
		offset,
	)
}

// _P9Same reports a decoded TIME that differs from the one written: it must be the same instant
// (time.Time.Equal), with the same offset, and it must be in time.UTC if and only if the
// original was (a zone that is not time.UTC, such as +00:00, comes back as a fixed zone).
//
// Revisions:
//   - 2026-10-19 15:58: initial creation
func _P9Same(
	t *testing.T,
	got,
	want time.Time,
) {
	t.Helper()

	if !got.Equal(want) || _P9ZoneKind(got) != _P9ZoneKind(want) {
		t.Fatalf(
			"decoded %s in %s, want %s in %s",
			got.Format(time.RFC3339Nano),
			_P9ZoneKind(got),
			want.Format(time.RFC3339Nano),
			_P9ZoneKind(want),
		)
	}
}
