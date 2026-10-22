package per_test

import (
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_HELD is the kind key in testing.json of testing/held.py: the three rows of review
// P29-3, from the Held types of testing.asn1. HELD_FROM is the FROM set of Held-From.
const (
	VECTOR_HELD = "held"
	HELD_FROM   = "ACGT"
)

// _HeldInput is the value of one held row: the bits of a BIT STRING, the octets of an OCTET
// STRING, or the text of a string, as hex or text.
type _HeldInput struct {
	Bits   string `json:"bits"`
	Length int    `json:"length"`
	Octets string `json:"octets"`
	Text   string `json:"text"`
}

// _HeldRow is one row of the held kind.
type _HeldRow struct {
	_Expected
	Type  string      `json:"type"`
	Input *_HeldInput `json:"input"`
}

// TestHeld_Vectors guards review P29-3: each held row encodes to the octets of the oracles
// and decodes back. Bits16 and Octets2 are a fixed size of exactly 16 bits after a BOOLEAN,
// which X.691 16.9 and 17.6 leave unaligned. From is a FROM alphabet of four characters,
// 2 bits each by their index (X.691 30.5.2 and 30.5.4).
//
// Revisions:
//   - 2026-10-21 18:08: initial creation (review P29-3)
func TestHeld_Vectors(t *testing.T) {
	var rows []*_HeldRow

	_Load(
		t,
		VECTOR_HELD,
		&rows,
	)

	checks := map[string]func(
		t *testing.T,
		aligned bool,
		row *_HeldRow,
	){
		"Bits16":  _CheckHeldBits,
		"Octets2": _CheckHeldOctets,
		"From":    _CheckHeldFrom,
	}

	if len(rows) != len(checks) {
		t.Fatalf(
			"%d rows under %q, want %d",
			len(rows),
			VECTOR_HELD,
			len(checks),
		)
	}

	for _, row := range rows {
		check, ok := checks[row.Type]
		if !ok {
			t.Fatalf(
				"no check for the row %q",
				row.Type,
			)
		}

		for _, aligned := range []bool{true, false} {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+row.Type,
				func(t *testing.T) {
					check(
						t,
						aligned,
						row,
					)
				},
			)
		}
	}
}

// _CheckHeldBits encodes TRUE and the 16 bits of the row, compares the octets, and decodes
// both back.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation
func _CheckHeldBits(
	t *testing.T,
	aligned bool,
	row *_HeldRow,
) {
	t.Helper()

	var (
		size = per.Constrained(
			int64(row.Input.Length),
			int64(row.Input.Length),
		)
		value = &asn1.BitString{
			Bytes: _HeldHex(
				t,
				row.Input.Bits,
			),
			BitLength: row.Input.Length,
		}

		enc = ENCODERS[aligned]()
	)
	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatal(err)
	}

	if err := enc.EncodeBitString(
		value,
		size,
	); err != nil {
		t.Fatal(err)
	}

	dec := DECODERS[aligned](row._Check(
		t,
		aligned,
		enc.Bytes(),
	))
	_HeldBoolean(
		t,
		dec,
	)

	back, err := dec.DecodeBitString(size)
	if err != nil || hex.EncodeToString(back.Bytes) != row.Input.Bits {
		t.Fatalf(
			"decoded %v, %v; want %s",
			back,
			err,
			row.Input.Bits,
		)
	}
}

// _CheckHeldOctets encodes TRUE and the 2 octets of the row, compares the octets, and
// decodes both back.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation
func _CheckHeldOctets(
	t *testing.T,
	aligned bool,
	row *_HeldRow,
) {
	t.Helper()

	var (
		value = _HeldHex(
			t,
			row.Input.Octets,
		)
		size = per.Constrained(
			int64(len(value)),
			int64(len(value)),
		)

		enc = ENCODERS[aligned]()
	)
	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatal(err)
	}

	if err := enc.EncodeOctetString(
		value,
		size,
	); err != nil {
		t.Fatal(err)
	}

	dec := DECODERS[aligned](row._Check(
		t,
		aligned,
		enc.Bytes(),
	))
	_HeldBoolean(
		t,
		dec,
	)

	back, err := dec.DecodeOctetString(size)
	if err != nil || hex.EncodeToString(back) != row.Input.Octets {
		t.Fatalf(
			"decoded %x, %v; want %s",
			back,
			err,
			row.Input.Octets,
		)
	}
}

// _CheckHeldFrom encodes the text of the row with the FROM alphabet, compares the octets,
// and decodes it back.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation
func _CheckHeldFrom(
	t *testing.T,
	aligned bool,
	row *_HeldRow,
) {
	t.Helper()

	alphabet, err := per.NewAlphabet(
		per.STRING_IA5,
		HELD_FROM,
	)
	if err != nil {
		t.Fatal(err)
	}

	enc := ENCODERS[aligned]()
	if err := enc.EncodeAlphabetString(
		row.Input.Text,
		alphabet,
		per.Unconstrained(),
	); err != nil {
		t.Fatal(err)
	}

	back, err := DECODERS[aligned](row._Check(
		t,
		aligned,
		enc.Bytes(),
	)).DecodeAlphabetString(
		alphabet,
		per.Unconstrained(),
	)
	if err != nil || back != row.Input.Text {
		t.Fatalf(
			"decoded %q, %v; want %q",
			back,
			err,
			row.Input.Text,
		)
	}
}

// _HeldBoolean reads the BOOLEAN in front of a held value, which must be TRUE.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation
func _HeldBoolean(
	t *testing.T,
	dec *per.Decoder,
) {
	t.Helper()

	bit, err := dec.DecodeBoolean()
	if err != nil || !bit {
		t.Fatalf(
			"BOOLEAN = %t, %v; want true",
			bit,
			err,
		)
	}
}

// _HeldHex turns the hex text of a row into octets.
//
// Revisions:
//   - 2026-10-21 18:08: initial creation
func _HeldHex(
	t *testing.T,
	text string,
) []byte {
	t.Helper()

	octets, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}

	return octets
}
