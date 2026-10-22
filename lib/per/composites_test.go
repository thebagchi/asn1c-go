package per_test

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_COMPOSITES is the kind key in testing.json of testing/composites.py, which asks pycrate
// 0.8.1 and Erlang/OTP 29.1.1 (testing.asn1) for the encoding of each
// value. A row of a long list keeps the sha256 and the length of each encoding,
// not its octets.
const (
	VECTOR_COMPOSITES = "composites"
)

// The kinds of component that the hand codecs of this phase know.
const (
	P7_BOOL = "bool"
	P7_INT  = "int"
	P7_STR  = "str"
	P7_NULL = "null"
)

// P7_ELEMENT is the INTEGER (0..255) of the lists and components; P7_TEXT is the
// IA5String (SIZE (1..8)).
var (
	P7_ELEMENT = per.Constrained(
		0,
		255,
	)
	P7_TEXT = per.Constrained(
		1,
		8,
	)
)

type _P7Row struct {
	Type       string          `json:"type"`
	Count      *int            `json:"count"`
	Value      json.RawMessage `json:"value"`
	Oracles    []string        `json:"oracles"`
	Agree      bool            `json:"agree"`
	DecidedBy  string          `json:"decided_by"`
	Aper       string          `json:"aper"`
	Uper       string          `json:"uper"`
	AperSha256 string          `json:"aper_sha256"`
	UperSha256 string          `json:"uper_sha256"`
	AperOctets int             `json:"aper_octets"`
	UperOctets int             `json:"uper_octets"`
	Answers    *_P7Answers     `json:"answers"`
}

// _P7Pair is the answer of pycrate (Py) and of Erlang (Er) for one variant. For a SET both
// keep the preamble bits in textual order, which X.691 21 and the user decision of
// 2026-10-19 do not follow; the row keeps them beside the expected octets.
type _P7Pair struct {
	Py json.RawMessage `json:"py"`
	Er json.RawMessage `json:"er"`
}

// _P7Hex returns the hex text of an answer, or "" for a long answer or none.
//
// Revisions:
//   - 2026-10-20 00:51: initial creation
func _P7Hex(answer json.RawMessage) string {
	var text string
	if err := json.Unmarshal(
		answer,
		&text,
	); err != nil {
		return ""
	}

	return text
}

// _P7Answers holds the answers of the oracles for both variants.
type _P7Answers struct {
	Aper *_P7Pair `json:"aper"`
	Uper *_P7Pair `json:"uper"`
}

type _P7File struct {
	Sequence  []*_P7Row `json:"sequence"`
	Extension []*_P7Row `json:"extension"`
	Set       []*_P7Row `json:"set"`
	Choice    []*_P7Row `json:"choice"`
	SeqOf     []*_P7Row `json:"seqof"`
}

// _P7Expected is the answer of the oracles for one variant: the octets, or the
// sha256 and length of the octets.
type _P7Expected struct {
	hex    string
	sha256 string
	octets int
}

// _P7Load reads testing.json (composites).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Load(t *testing.T) *_P7File {
	t.Helper()

	var file _P7File

	_Load(
		t,
		VECTOR_COMPOSITES,
		&file,
	)

	return &file
}

// _P7Of returns the rows of one type.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Of(
	rows []*_P7Row,
	names ...string,
) []*_P7Row {
	var out []*_P7Row

	for _, row := range rows {
		for _, name := range names {
			if row.Type == name {
				out = append(
					out,
					row,
				)
			}
		}
	}

	return out
}

// _P7Name names a row for a subtest.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Name(
	row *_P7Row,
	index int,
) string {
	if row.Count != nil {
		return fmt.Sprintf(
			"%s_%d",
			row.Type,
			*row.Count,
		)
	}

	return fmt.Sprintf(
		"%s_%d",
		row.Type,
		index,
	)
}

// _P7Want returns the expected answer for a variant.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Want(
	row *_P7Row,
	aligned bool,
) *_P7Expected {
	return map[bool]*_P7Expected{
		true: {
			hex:    row.Aper,
			sha256: row.AperSha256,
			octets: row.AperOctets,
		},
		false: {
			hex:    row.Uper,
			sha256: row.UperSha256,
			octets: row.UperOctets,
		},
	}[aligned]
}

// _P7Check compares an encoding with the answer of the oracles.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Check(
	t *testing.T,
	row *_P7Row,
	aligned bool,
	got []byte,
) {
	t.Helper()

	want := _P7Want(
		row,
		aligned,
	)

	if want.hex != "" {
		_Compare(
			t,
			got,
			_Unhex(
				t,
				want.hex,
			),
		)

		return
	}

	sum := sha256.Sum256(got)

	if text := hex.EncodeToString(sum[:]); text != want.sha256 || len(got) != want.octets {
		t.Fatalf(
			"%d octets, sha256 %s, want %d, %s",
			len(got),
			text,
			want.octets,
			want.sha256,
		)
	}
}

// _P7Bits makes the caller-owned bits of a preamble or an additions bitmap: all
// zero, sized for count bits.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Bits(count int) *asn1.BitString {
	return &asn1.BitString{
		Bytes: make(
			[]byte,
			(count+7)/8,
		),
		BitLength: count,
	}
}

// _P7Mark sets bit index, counted from the leading bit (X.680 22.2).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Mark(
	bits *asn1.BitString,
	index int,
) {
	bits.Bytes[index/8] |= 0x80 >> (index % 8)
}

// _P7WriteScalar writes one value of a kind the way generated code would.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7WriteScalar(
	enc *per.Encoder,
	kind string,
	value any,
) error {
	switch kind {
	case P7_BOOL:
		return enc.EncodeBoolean(value.(bool))
	case P7_INT:
		return enc.EncodeInteger(
			value.(int64),
			P7_ELEMENT,
		)
	case P7_STR:
		return enc.EncodeRestrictedString(
			value.(string),
			per.STRING_IA5,
			P7_TEXT,
		)
	}

	return enc.EncodeNull()
}

// _P7ReadScalar reads one value of a kind.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7ReadScalar(
	dec *per.Decoder,
	kind string,
) (any, error) {
	switch kind {
	case P7_BOOL:
		return dec.DecodeBoolean()
	case P7_INT:
		return dec.DecodeInteger(P7_ELEMENT)
	case P7_STR:
		return dec.DecodeRestrictedString(
			per.STRING_IA5,
			P7_TEXT,
		)
	}

	return true, dec.DecodeNull()
}

// _P7Typed turns a JSON scalar into the Go value of its kind.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Typed(
	t *testing.T,
	kind string,
	raw any,
) any {
	t.Helper()

	switch kind {
	case P7_INT:
		return int64(raw.(float64))
	case P7_BOOL, P7_STR, P7_NULL:
		return raw
	}

	t.Fatalf(
		"unknown kind %q",
		kind,
	)

	return nil
}
