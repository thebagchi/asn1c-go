package per_test

import (
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// COUNT_RESERVATION_CAP is the most components that Count.Reservation may ask a
// decoder to allocate for one part.
const (
	COUNT_RESERVATION_CAP = 1024
)

// _P7List describes a SEQUENCE OF or SET OF type: the PER-visible size
// constraint and the kind of its component.
type _P7List struct {
	size *per.Constraint
	kind string
}

// _P7Part is what a Count says about one part of a list.
type _P7Part struct {
	start int
	end   int
	more  bool
}

// P7_LISTS holds the SEQUENCE OF and SET OF types of testing.asn1. SET
// OF is encoded as SEQUENCE OF in BASIC-PER (X.691 22.2).
var (
	P7_LISTS = map[string]*_P7List{
		"SeqNo": {
			size: per.Unconstrained(),
			kind: P7_INT,
		},
		"Seq3": {
			size: per.Constrained(
				3,
				3,
			),
			kind: P7_INT,
		},
		"Seq10": {
			size: per.Constrained(
				0,
				10,
			),
			kind: P7_INT,
		},
		"SeqExt": {
			size: per.Constrained(
				1,
				5,
			).Extensible(),
			kind: P7_INT,
		},
		"Seq70k": {
			size: per.Constrained(
				0,
				70000,
			),
			kind: P7_INT,
		},
		"SeqBool": {
			size: per.Unconstrained(),
			kind: P7_BOOL,
		},
		"SetNo": {
			size: per.Unconstrained(),
			kind: P7_INT,
		},
		"SetExt": {
			size: per.Constrained(
				1,
				5,
			).Extensible(),
			kind: P7_INT,
		},
	}
)

// _P7Component is the value of component i: (i*7 + 3) mod 256 for an INTEGER,
// and true for every third BOOLEAN (the rule of testing/composites.py).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Component(
	kind string,
	index int,
) any {
	if kind == P7_BOOL {
		return index%3 == 0
	}

	return int64((index*7 + 3) % 256)
}

// _P7EncodeList writes a list the way generated code does: EncodeCount, the
// components of the part, then EncodeNext while More says another length
// follows (X.691 20.6, 11.9.3.8). It returns what Count said for each part.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7EncodeList(
	enc *per.Encoder,
	list *_P7List,
	total int,
) ([]_P7Part, error) {
	var (
		count per.Count
		parts []_P7Part
	)

	if err := enc.EncodeCount(
		&count,
		uint64(total),
		list.size,
	); err != nil {
		return nil, err
	}

	for {
		parts = append(
			parts,
			_P7Part{
				start: count.Start(),
				end:   count.End(),
				more:  count.More(),
			},
		)

		for index := count.Start(); index < count.End(); index++ {
			if err := _P7WriteScalar(
				enc,
				list.kind,
				_P7Component(
					list.kind,
					index,
				),
			); err != nil {
				return parts, err
			}
		}

		if !count.More() {
			return parts, nil
		}

		if err := enc.EncodeNext(&count); err != nil {
			return parts, err
		}
	}
}

// _P7DecodeList reads a list and checks every component against the rule. It
// returns what Count said for each part.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7DecodeList(
	dec *per.Decoder,
	list *_P7List,
	total int,
) ([]_P7Part, error) {
	var (
		count per.Count
		parts []_P7Part
	)

	if err := dec.DecodeCount(
		&count,
		list.size,
	); err != nil {
		return nil, err
	}

	items := make(
		[]any,
		0,
		count.Reservation(),
	)

	for {
		parts = append(
			parts,
			_P7Part{
				start: count.Start(),
				end:   count.End(),
				more:  count.More(),
			},
		)

		for index := count.Start(); index < count.End(); index++ {
			item, err := _P7ReadScalar(
				dec,
				list.kind,
			)
			if err != nil {
				return parts, err
			}

			items = append(
				items,
				item,
			)
		}

		if !count.More() {
			break
		}

		if err := dec.DecodeNext(&count); err != nil {
			return parts, err
		}
	}

	return parts, _P7CheckList(
		items,
		list,
		total,
	)
}

// _P7CheckList compares the components read with the rule.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7CheckList(
	items []any,
	list *_P7List,
	total int,
) error {
	if len(items) != total {
		return fmt.Errorf(
			"%d components, want %d",
			len(items),
			total,
		)
	}

	for index, item := range items {
		if item != _P7Component(
			list.kind,
			index,
		) {
			return fmt.Errorf(
				"component %d = %v",
				index,
				item,
			)
		}
	}

	return nil
}

// TestCount_Vectors checks SEQUENCE OF and SET OF against the octets of pycrate
// and OTP. Counts: 0, 1, 3, 10, 11, around 127 and 128 (the 11.9.3.6 and
// 11.9.3.7 length forms), 16383, 16384, 16385, 32768, 65536, 65537, 70000,
// 131072 and 147457 (three full fragments of 64K, 64K and 16K, then one: X.691
// 11.9.3.8.1 note 2) for no SIZE and SIZE(0..70000); the root and the extension
// of SIZE(1..5,...), whose extension bit comes first (20.4) and whose count
// out of the root has the form of an unconstrained length; SIZE(3), which has no
// length (20.5); SIZE(0..10), whose length is a bit-field (11.9.3.3). The
// component of index i is (i*7 + 3) mod 256, a BOOLEAN is true for every third
// index. Long answers are kept as sha256. pycrate fails on 16K components or
// more, so OTP answers those rows; neither oracle can answer the extension of
// SIZE(1..5,...) from 16384 components (testing/composites.py derives the octets
// from the unconstrained answer of OTP, 20.4). A list whose length is a multiple
// of 16K ends with the zero length of 11.9.3.8.3.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestCount_Vectors(t *testing.T) {
	file := _P7Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.SeqOf {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						list = P7_LISTS[row.Type]
						enc  = ENCODERS[aligned]()
					)

					if _, err := _P7EncodeList(
						enc,
						list,
						*row.Count,
					); err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					_P7Check(
						t,
						row,
						aligned,
						enc.Bytes(),
					)

					if _, err := _P7DecodeList(
						DECODERS[aligned](enc.Bytes()),
						list,
						*row.Count,
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
}

// TestCount_Framed writes each list between BOOLEAN fields, so that a decoder
// that stops one component early or late, or does not read the terminator of
// 11.9.3.8.3, shows in the field that follows.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestCount_Framed(t *testing.T) {
	file := _P7Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.SeqOf {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					list := P7_LISTS[row.Type]

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							_, err := _P7EncodeList(
								enc,
								list,
								*row.Count,
							)

							return err
						},
						func(dec *per.Decoder) error {
							_, err := _P7DecodeList(
								dec,
								list,
								*row.Count,
							)

							return err
						},
					)
				},
			)
		}
	}
}

// P7_PARTS holds what a Count says for lists with no SIZE (X.691 11.9.3.8): a
// part of 1 to 4 times 16K components while 16K or more are left, then the
// rest. More is true after each part that a length follows: after a full part
// always, so a list of exactly 16K, 32K, 48K or 64K components has a last part
// of no components, which is the zero length of 11.9.3.8.3.
var (
	P7_PARTS = map[int][]_P7Part{
		0: {
			{
				start: 0,
				end:   0,
				more:  false,
			},
		},
		127: {
			{
				start: 0,
				end:   127,
				more:  false,
			},
		},
		16383: {
			{
				start: 0,
				end:   16383,
				more:  false,
			},
		},
		16384: {
			{
				start: 0,
				end:   16384,
				more:  true,
			},
			{
				start: 16384,
				end:   16384,
				more:  false,
			},
		},
		16385: {
			{
				start: 0,
				end:   16384,
				more:  true,
			},
			{
				start: 16384,
				end:   16385,
				more:  false,
			},
		},
		32768: {
			{
				start: 0,
				end:   32768,
				more:  true,
			},
			{
				start: 32768,
				end:   32768,
				more:  false,
			},
		},
		65536: {
			{
				start: 0,
				end:   65536,
				more:  true,
			},
			{
				start: 65536,
				end:   65536,
				more:  false,
			},
		},
		70000: {
			{
				start: 0,
				end:   65536,
				more:  true,
			},
			{
				start: 65536,
				end:   70000,
				more:  false,
			},
		},
		147457: {
			{
				start: 0,
				end:   65536,
				more:  true,
			},
			{
				start: 65536,
				end:   131072,
				more:  true,
			},
			{
				start: 131072,
				end:   147456,
				more:  true,
			},
			{
				start: 147456,
				end:   147457,
				more:  false,
			},
		},
	}
)

// TestCount_Parts checks the parts that Count reports, for the encoder and for
// the decoder, in both variants: the choice of the part is the one of X.691
// 11.9.3.8.1 (the largest multiple of 16K, at most 64K, that the rest holds), and
// the part after a full one may be empty (11.9.3.8.3). The list of 147457
// components is the note of 11.9.3.8.1: 64K, 64K, 16K, then one.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestCount_Parts(t *testing.T) {
	list := P7_LISTS["SeqNo"]

	for _, aligned := range []bool{true, false} {
		for total, want := range P7_PARTS {
			t.Run(
				fmt.Sprintf(
					"%s_%d",
					VARIANT_NAMES[aligned],
					total,
				),
				func(t *testing.T) {
					var (
						enc = ENCODERS[aligned]()

						written, err = _P7EncodeList(
							enc,
							list,
							total,
						)
					)
					if err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					read, err := _P7DecodeList(
						DECODERS[aligned](enc.Bytes()),
						list,
						total,
					)
					if err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					for name, got := range map[string][]_P7Part{
						"encoder": written,
						"decoder": read,
					} {
						if fmt.Sprint(got) != fmt.Sprint(want) {
							t.Errorf(
								"%s parts %v, want %v",
								name,
								got,
								want,
							)
						}
					}
				},
			)
		}
	}
}

// TestCount_FixedAndBounded checks the parts of the types with a SIZE that has an
// upper bound below 64K: one part, with no More, whatever the count (X.691 20.5
// and 11.9.3.3; the fragmentation of 11.9.3.8 starts at an unbounded length).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestCount_FixedAndBounded(t *testing.T) {
	cases := []struct {
		name  string
		total int
	}{
		{
			name:  "Seq3",
			total: 3,
		},
		{
			name:  "Seq10",
			total: 0,
		},
		{
			name:  "Seq10",
			total: 10,
		},
		{
			name:  "SeqExt",
			total: 5,
		},
		{
			name:  "SeqExt",
			total: 6,
		},
	}

	for _, aligned := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(
				fmt.Sprintf(
					"%s_%s_%d",
					VARIANT_NAMES[aligned],
					tc.name,
					tc.total,
				),
				func(t *testing.T) {
					var (
						enc = ENCODERS[aligned]()

						parts, err = _P7EncodeList(
							enc,
							P7_LISTS[tc.name],
							tc.total,
						)
					)
					if err != nil {
						t.Fatalf(
							"encode = %v",
							err,
						)
					}

					want := []_P7Part{{
						start: 0,
						end:   tc.total,
						more:  false,
					}}
					if fmt.Sprint(parts) != fmt.Sprint(want) {
						t.Fatalf(
							"parts %v, want %v",
							parts,
							want,
						)
					}
				},
			)
		}
	}
}
