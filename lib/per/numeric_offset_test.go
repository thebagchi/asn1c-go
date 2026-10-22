package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_NUMERIC_OFFSET is the kind key in testing.json of testing/numeric_offset.py. Its
// rows are a NumericString after k BOOLEAN bits, k = 0 to 7, from the Numoff types of
// testing.asn1. NUMERIC_RANGE_SLACK is the room the R form adds above the length.
const (
	VECTOR_NUMERIC_OFFSET = "numeric_offset"
	NUMERIC_RANGE_SLACK   = 7
)

// _OffsetRow is one row of the numeric_offset kind: the expected octets, the number of
// BOOLEAN bits in front, the SIZE form (U, F or R), and the length and seed of the value.
type _OffsetRow struct {
	_Expected
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Form   string `json:"form"`
	Length int    `json:"length"`
	Seed   int    `json:"seed"`
}

// TestNumericString_Offsets encodes a NumericString at every bit offset and compares the
// octets with pycrate and Erlang/OTP. The packed characters leave the kernel as a byte string,
// and the bit buffer must place that string at any offset (X.691 30.5). The value is read back
// after the same BOOLEAN bits, so a decoder that is one bit off fails too.
//
// Revisions:
//   - 2026-10-20 13:59: initial creation; replaces the golden file of an earlier encoder
func TestNumericString_Offsets(t *testing.T) {
	var rows []*_OffsetRow

	_Load(
		t,
		VECTOR_NUMERIC_OFFSET,
		&rows,
	)

	if len(rows) == 0 {
		t.Fatalf(
			"no rows under %q",
			VECTOR_NUMERIC_OFFSET,
		)
	}

	for _, row := range rows {
		for _, aligned := range []bool{true, false} {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+row.Type,
				func(t *testing.T) {
					_CheckOffsetRow(
						t,
						aligned,
						row,
					)
				},
			)
		}
	}
}

// _CheckOffsetRow encodes one row, compares the octets, and decodes the value back.
//
// Revisions:
//   - 2026-10-20 13:59: initial creation
func _CheckOffsetRow(
	t *testing.T,
	aligned bool,
	row *_OffsetRow,
) {
	t.Helper()

	var (
		value = _NumericText(
			row.Length,
			row.Seed,
		)
		size = _OffsetSize(row)

		enc = ENCODERS[aligned]()
	)
	for range row.Offset {
		if err := enc.EncodeBoolean(true); err != nil {
			t.Fatal(err)
		}
	}

	err := enc.EncodeRestrictedString(
		value,
		per.STRING_NUMERIC,
		size,
	)
	if err != nil {
		t.Fatalf(
			"encode: %v",
			err,
		)
	}

	encoded := enc.Bytes()
	row._Check(
		t,
		aligned,
		encoded,
	)

	_CheckOffsetDecode(
		t,
		DECODERS[aligned](encoded),
		row,
		value,
	)
}

// _CheckOffsetDecode reads the BOOLEAN bits and the value of one row.
//
// Revisions:
//   - 2026-10-20 13:59: initial creation
func _CheckOffsetDecode(
	t *testing.T,
	dec *per.Decoder,
	row *_OffsetRow,
	want string,
) {
	t.Helper()

	for range row.Offset {
		bit, err := dec.DecodeBoolean()
		if err != nil || !bit {
			t.Fatalf(
				"decode BOOLEAN = %t, %v; want true",
				bit,
				err,
			)
		}
	}

	got, err := dec.DecodeRestrictedString(
		per.STRING_NUMERIC,
		_OffsetSize(row),
	)
	if err != nil {
		t.Fatalf(
			"decode: %v",
			err,
		)
	}

	if got != want {
		t.Fatalf(
			"decode = %q, want %q",
			got,
			want,
		)
	}
}

// _OffsetSize returns the SIZE constraint of a row's form: none, SIZE (n), or SIZE (0..n+7).
//
// Revisions:
//   - 2026-10-20 13:59: initial creation
func _OffsetSize(row *_OffsetRow) *per.Constraint {
	switch row.Form {
	case "F":
		return per.Constrained(
			int64(row.Length),
			int64(row.Length),
		)
	case "R":
		return per.Constrained(
			0,
			int64(row.Length+NUMERIC_RANGE_SLACK),
		)
	default:
		return per.Unconstrained()
	}
}
