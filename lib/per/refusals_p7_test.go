package per_test

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// ALLOC_PHASE7_MAX is the most that a decode with a false length may allocate.
// With COUNT_RESERVATION_CAP components of 16 octets a reservation is 16K.
const (
	ALLOC_PHASE7_MAX = 1 << 18
)

// ErrReservationP7 reports a Count whose Reservation is above its cap.
var (
	ErrReservationP7 = errors.New("reservation is above the cap or the part")
)

// TestRefusals_CountOutOfRange checks that EncodeCount refuses a count outside
// the size constraint with ErrValueOutOfRange (X.691 20.2, 20.4: only an
// extensible SIZE takes a count outside its root), and accepts the counts at the
// edges.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_CountOutOfRange(t *testing.T) {
	cases := []struct {
		name  string
		list  string
		total uint64
		fails bool
	}{
		{
			name:  "fixed_below",
			list:  "Seq3",
			total: 2,
			fails: true,
		},
		{
			name:  "fixed_above",
			list:  "Seq3",
			total: 4,
			fails: true,
		},
		{
			name:  "fixed_control",
			list:  "Seq3",
			total: 3,
			fails: false,
		},
		{
			name:  "bounded_above",
			list:  "Seq10",
			total: 11,
			fails: true,
		},
		{
			name:  "bounded_control",
			list:  "Seq10",
			total: 10,
			fails: false,
		},
		{
			name:  "large_above",
			list:  "Seq70k",
			total: 70001,
			fails: true,
		},
		{
			name:  "large_control",
			list:  "Seq70k",
			total: 70000,
			fails: false,
		},
		{
			name:  "extensible_control",
			list:  "SeqExt",
			total: 11,
			fails: false,
		},
		{
			name:  "extensible_zero",
			list:  "SeqExt",
			total: 0,
			fails: false,
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					var count per.Count

					err := ENCODERS[aligned]().EncodeCount(
						&count,
						tc.total,
						P7_LISTS[tc.list].size,
					)

					if tc.fails && !errors.Is(
						err,
						per.ErrValueOutOfRange,
					) {
						t.Fatalf(
							"EncodeCount(%d) = %v, want range error",
							tc.total,
							err,
						)
					}

					if !tc.fails && err != nil {
						t.Fatalf(
							"EncodeCount(%d) = %v",
							tc.total,
							err,
						)
					}
				},
			)
		}
	}
}

// TestRefusals_CountDecode checks the decoder of the length: a length outside
// the size constraint (the 4-bit field 1011 is 11 under SIZE(0..10)) is refused
// with ErrValueOutOfRange, and a fragment multiplier of 0 or above 4 with
// ErrFragmentCount (X.691 11.9.3.8). The inputs are not encodings of any value,
// so no oracle has an answer for them. The control reads a valid length.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_CountDecode(t *testing.T) {
	cases := []struct {
		name string
		list string
		data []byte
		want error
	}{
		{
			name: "above_upper_bound",
			list: "Seq10",
			data: []byte{0xB0},
			want: per.ErrValueOutOfRange,
		},
		{
			name: "multiplier_zero",
			list: "SeqNo",
			data: []byte{0xC0},
			want: per.ErrFragmentCount,
		},
		{
			name: "multiplier_five",
			list: "SeqNo",
			data: []byte{0xC5},
			want: per.ErrFragmentCount,
		},
		{
			name: "control",
			list: "Seq10",
			data: []byte{0x50},
			want: nil,
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					var count per.Count

					err := DECODERS[aligned](tc.data).DecodeCount(
						&count,
						P7_LISTS[tc.list].size,
					)

					if tc.want == nil && (err != nil || count.End() != 5) {
						t.Fatalf(
							"DecodeCount = %v, End %d, want 5",
							err,
							count.End(),
						)
					}

					if tc.want != nil && !errors.Is(
						err,
						tc.want,
					) {
						t.Fatalf(
							"DecodeCount = %v, want %v",
							err,
							tc.want,
						)
					}
				},
			)
		}
	}
}

// TestRefusals_FalseCount checks the decoder against a false length on a short
// input: a length that claims 16383 or 64K components and no component behind it.
// DecodeCount may refuse, or accept the length; if it accepts it, Reservation is
// not above the cap of COUNT_RESERVATION_CAP components nor above the part, the
// reading of the components fails, and the whole decode allocates a few KB, not
// the size that the length asks for.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_FalseCount(t *testing.T) {
	cases := []struct {
		name string
		list string
		data []byte
	}{
		{
			name: "two_octet_length",
			list: "SeqNo",
			data: []byte{0xBF, 0xFF},
		},
		{
			name: "fragment_of_64K",
			list: "SeqNo",
			data: []byte{0xC4},
		},
		{
			name: "fragment_of_64K_bool",
			list: "SeqBool",
			data: []byte{0xC4},
		},
		{
			name: "fragment_of_16K_large_bound",
			list: "Seq70k",
			data: []byte{0xC1},
		},
		{
			name: "one_octet_length",
			list: "SeqNo",
			data: []byte{0x7F},
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					var (
						before runtime.MemStats
						after  runtime.MemStats
					)

					runtime.ReadMemStats(&before)

					err := _P7ReadFalse(
						DECODERS[aligned](tc.data),
						P7_LISTS[tc.list],
					)

					runtime.ReadMemStats(&after)

					if errors.Is(
						err,
						ErrReservationP7,
					) {
						t.Fatalf("Reservation is above its cap")
					}

					if err == nil {
						t.Fatalf("a false length decoded without an error")
					}

					used := after.TotalAlloc - before.TotalAlloc
					if used > ALLOC_PHASE7_MAX {
						t.Fatalf(
							"decode allocated %d bytes, max %d",
							used,
							ALLOC_PHASE7_MAX,
						)
					}
				},
			)
		}
	}
}

// TestRefusals_FalseCountControl reads an honest list of 3 components with the
// same function, so that TestRefusals_FalseCount cannot pass on a decoder that
// always fails: the list decodes without an error and its reservation is 3 at
// most.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_FalseCountControl(t *testing.T) {
	list := P7_LISTS["SeqNo"]

	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned],
			func(t *testing.T) {
				enc := ENCODERS[aligned]()

				if _, err := _P7EncodeList(
					enc,
					list,
					3,
				); err != nil {
					t.Fatalf(
						"encode = %v",
						err,
					)
				}

				if err := _P7ReadFalse(
					DECODERS[aligned](enc.Bytes()),
					list,
				); err != nil {
					t.Fatalf(
						"decode = %v",
						err,
					)
				}
			},
		)
	}
}

// _P7ReadFalse decodes a list as a decoder of generated code does, with the
// reservation of Count, and checks the reservation.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7ReadFalse(
	dec *per.Decoder,
	list *_P7List,
) error {
	var count per.Count

	if err := dec.DecodeCount(
		&count,
		list.size,
	); err != nil {
		return err
	}

	if count.Reservation() > COUNT_RESERVATION_CAP ||
		count.Reservation() > count.End()-count.Start() {
		return ErrReservationP7
	}

	items := make(
		[]any,
		0,
		count.Reservation(),
	)

	for index := count.Start(); index < count.End(); index++ {
		item, err := _P7ReadScalar(
			dec,
			list.kind,
		)
		if err != nil {
			return err
		}

		items = append(
			items,
			item,
		)
	}

	_ = items

	return nil
}

// TestRefusals_Additions checks DecodeAdditions on input that no encoder writes:
// no input, a bitmap longer than the input, a length of 0 (X.691 19.8 note: n
// cannot be 0), and lengths of 16383 and of a 16K fragment with no bits behind
// them. All are refused; the control reads a valid bitmap and finds no unknown
// addition. EncodeAdditions refuses nil, a bitmap of 0 bits, and bits that the
// caller has not allocated.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_Additions(t *testing.T) {
	inputs := map[string]map[bool][]byte{
		"empty": {
			true:  {},
			false: {},
		},
		"bitmap_longer_than_input": {
			true:  {0x0E},
			false: {0x0E},
		},
		"length_zero": {
			true:  {0x80, 0x00},
			false: {0x80, 0x00},
		},
		"length_16383": {
			true:  {0x80, 0xBF, 0xFF},
			false: {0xDF, 0xFF, 0x80},
		},
		"fragment_16K": {
			true:  {0x80, 0xC1},
			false: {0xE0, 0x80},
		},
	}

	for _, aligned := range []bool{true, false} {
		for name, data := range inputs {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+name,
				func(t *testing.T) {
					var (
						dec = DECODERS[aligned](data[aligned])

						unknown, err = dec.DecodeAdditions(_P7Bits(3))
					)
					if err == nil {
						t.Fatalf(
							"DecodeAdditions = %d, nil, want an error",
							unknown,
						)
					}
				},
			)
		}

		t.Run(
			VARIANT_NAMES[aligned]+"_control",
			func(t *testing.T) {
				bits := _P7Bits(3)
				_P7Mark(
					bits,
					1,
				)

				enc := ENCODERS[aligned]()
				if err := enc.EncodeAdditions(bits); err != nil {
					t.Fatalf(
						"EncodeAdditions = %v",
						err,
					)
				}

				var (
					got = _P7Bits(3)

					unknown, err = DECODERS[aligned](
						enc.Bytes(),
					).DecodeAdditions(
						got,
					)
				)
				if err != nil || unknown != 0 || got.At(1) != 1 {
					t.Fatalf(
						"DecodeAdditions = %d, %v, bits %x",
						unknown,
						err,
						got.Bytes,
					)
				}
			},
		)
	}
}

// TestRefusals_EncodeBits checks that EncodePreamble and EncodeAdditions refuse
// bits that cannot be written: nil, with ErrNilValue; bits whose Bytes hold fewer
// than BitLength bits; and, for the additions, a BitLength of 0 (X.691 19.8 note).
// A preamble of 0 bits is valid (a SEQUENCE with no OPTIONAL or DEFAULT component)
// and writes nothing. DecodePreamble refuses a short Bytes and a short input.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_EncodeBits(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		t.Run(
			VARIANT_NAMES[aligned],
			func(t *testing.T) {
				enc := ENCODERS[aligned]()

				if err := enc.EncodePreamble(nil); !errors.Is(
					err,
					per.ErrNilValue,
				) {
					t.Errorf(
						"EncodePreamble(nil) = %v, want ErrNilValue",
						err,
					)
				}

				if err := enc.EncodeAdditions(nil); !errors.Is(
					err,
					per.ErrNilValue,
				) {
					t.Errorf(
						"EncodeAdditions(nil) = %v, want ErrNilValue",
						err,
					)
				}

				short := _P7Bits(9)
				short.Bytes = short.Bytes[:1]

				if err := enc.EncodePreamble(short); err == nil {
					t.Errorf("EncodePreamble(9 bits in 1 octet) = nil")
				}

				if err := enc.EncodeAdditions(short); err == nil {
					t.Errorf("EncodeAdditions(9 bits in 1 octet) = nil")
				}

				if err := enc.EncodeAdditions(_P7Bits(0)); err == nil {
					t.Errorf("EncodeAdditions(0 bits) = nil")
				}

				if err := enc.EncodePreamble(_P7Bits(0)); err != nil {
					t.Errorf(
						"EncodePreamble(0 bits) = %v",
						err,
					)
				}

				dec := DECODERS[aligned]([]byte{0})

				if err := dec.DecodePreamble(short); err == nil {
					t.Errorf("DecodePreamble(9 bits in 1 octet) = nil")
				}

				none := DECODERS[aligned]([]byte{})

				if err := none.DecodePreamble(_P7Bits(3)); err == nil {
					t.Errorf("DecodePreamble(no input) = nil")
				}
			},
		)
	}
}

// TestRefusals_OpenType checks DecodeOpenType and SkipOpenTypes on input that ends
// inside the open type: no input, a length with no octets, a length of 5 with 3
// octets, the first fragment of a 16385 octet value cut in its middle, and
// SkipOpenTypes of 3 over 2. Each case has a control that reads the same data
// whole.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestRefusals_OpenType(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		for _, size := range []int{5, 16385} {
			t.Run(
				fmt.Sprintf(
					"%s_%d",
					VARIANT_NAMES[aligned],
					size,
				),
				func(t *testing.T) {
					_P7CheckTruncated(
						t,
						aligned,
						_FragmentOctets(size),
					)
				},
			)
		}

		t.Run(
			VARIANT_NAMES[aligned]+"_no_input",
			func(t *testing.T) {
				none := DECODERS[aligned]([]byte{})

				if _, err := none.DecodeOpenType(); err == nil {
					t.Errorf("DecodeOpenType(no input) = nil")
				}

				if err := none.SkipOpenTypes(1); err == nil {
					t.Errorf("SkipOpenTypes(1, no input) = nil")
				}
			},
		)
	}
}

// _P7CheckTruncated writes an open type of the inner octets and checks that the
// whole is read, and that every shorter prefix is refused by DecodeOpenType and by
// SkipOpenTypes, and that SkipOpenTypes of 2 over 1 is refused.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7CheckTruncated(
	t *testing.T,
	aligned bool,
	inner []byte,
) {
	t.Helper()

	enc := ENCODERS[aligned]()

	if err := enc.EncodeOpenType(inner); err != nil {
		t.Fatalf(
			"EncodeOpenType = %v",
			err,
		)
	}

	whole := enc.Bytes()

	if _, err := DECODERS[aligned](whole).DecodeOpenType(); err != nil {
		t.Fatalf(
			"control: DecodeOpenType = %v",
			err,
		)
	}

	if err := DECODERS[aligned](whole).SkipOpenTypes(1); err != nil {
		t.Fatalf(
			"control: SkipOpenTypes(1) = %v",
			err,
		)
	}

	if err := DECODERS[aligned](whole).SkipOpenTypes(2); err == nil {
		t.Errorf("SkipOpenTypes(2) over one open type = nil")
	}

	for _, cut := range []int{1, 2, len(whole) / 2, len(whole) - 2} {
		if cut <= 0 || cut >= len(whole) {
			continue
		}

		if _, err := DECODERS[aligned](whole[:cut]).DecodeOpenType(); err == nil {
			t.Errorf(
				"DecodeOpenType(%d of %d octets) = nil",
				cut,
				len(whole),
			)
		}

		if err := DECODERS[aligned](whole[:cut]).SkipOpenTypes(1); err == nil {
			t.Errorf(
				"SkipOpenTypes(1) of %d of %d octets = nil",
				cut,
				len(whole),
			)
		}
	}
}
