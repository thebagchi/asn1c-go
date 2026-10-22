package per_test

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"slices"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_PDVS is the kind key in testing.json of testing/pdvs.py, which asks pycrate 0.8.1 and
// Erlang/OTP 29.1.1
// (the types Pdvs-* of testing.asn1) for the encoding of each value. The expected octets
// are the answers for the SEQUENCE that the clause names: X.691 28.3 (PdvSeq), 31.3 (CsSeq),
// 29.1 (ExtSeq) and X.681 C.7 (InstSeq). The answers of the built-in types are in the file as
// records: OTP agrees on every row, pycrate does not (it keeps the OPTIONAL bit of
// data-value-descriptor that 28.3 and 31.3 remove, and its EXTERNAL is the identification form
// of X.680 37.5), so the clause decides.
const (
	VECTOR_PDVS = "pdvs"
)

// The kinds of row of testing.json (pdvs).
const (
	P8_PDV        = "pdv"
	P8_CS         = "cs"
	P8_EXT        = "ext"
	P8_NEITHER    = "neither"
	P8_INST       = "inst"
	P8_PREDEFINED = "predefined"
)

// The alternatives of the identification and of the encoding, as the file spells them.
const (
	P8_SYNTAXES                = "syntaxes"
	P8_SYNTAX                  = "syntax"
	P8_PRESENTATION_CONTEXT_ID = "presentation-context-id"
	P8_CONTEXT_NEGOTIATION     = "context-negotiation"
	P8_TRANSFER_SYNTAX         = "transfer-syntax"
	P8_FIXED                   = "fixed"
	P8_SINGLE_ASN1_TYPE        = "single-ASN1-type"
	P8_OCTET_ALIGNED           = "octet-aligned"
	P8_ARBITRARY               = "arbitrary"
)

// P8_BIT_MULTIPLIER, P8_BIT_OFFSET and P8_BIT_MODULUS are the rule of the arbitrary BIT STRING of
// pdvs.py: bit i is 1 when (i * 7 + 3) mod 5 is below P8_BIT_LIMIT.
const (
	P8_BIT_MULTIPLIER = 7
	P8_BIT_OFFSET     = 3
	P8_BIT_MODULUS    = 5
	P8_BIT_LIMIT      = 2
)

// P8_SHORT_ROW is the length in octets up to which the truncation test cuts a row at every
// octet; a longer row is cut at a few places.
const (
	P8_SHORT_ROW = 80
)

type _P8Data struct {
	Hex   *string `json:"hex"`
	Count *int    `json:"count"`
}

type _P8Ident struct {
	Alt      string `json:"alt"`
	Abstract []int  `json:"abstract"`
	Transfer []int  `json:"transfer"`
	OID      []int  `json:"oid"`
	ID       int64  `json:"id"`
}

type _P8EncodingRow struct {
	Alt   string   `json:"alt"`
	Data  *_P8Data `json:"data"`
	Bits  int      `json:"bits"`
	Inner *string  `json:"inner"`
}

type _P8Row struct {
	Type           string          `json:"type"`
	Identification *_P8Ident       `json:"identification"`
	Data           *_P8Data        `json:"data"`
	Descriptor     *string         `json:"descriptor"`
	Encoding       *_P8EncodingRow `json:"encoding"`
	TypeID         []int           `json:"type_id"`
	Inner          *string         `json:"inner"`
	Oracles        []string        `json:"oracles"`
	Agree          bool            `json:"agree"`
	Clause         string          `json:"clause"`
	DecidedBy      string          `json:"decided_by"`
	Aper           string          `json:"aper"`
	Uper           string          `json:"uper"`
	AperSha256     string          `json:"aper_sha256"`
	UperSha256     string          `json:"uper_sha256"`
	AperOctets     int             `json:"aper_octets"`
	UperOctets     int             `json:"uper_octets"`
}

type _P8File struct {
	Pdv        []*_P8Row `json:"pdv"`
	Cs         []*_P8Row `json:"cs"`
	Ext        []*_P8Row `json:"ext"`
	Neither    []*_P8Row `json:"neither"`
	Inst       []*_P8Row `json:"inst"`
	Predefined []*_P8Row `json:"predefined"`
}

// _P8Load reads testing.json (pdvs).
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Load(t *testing.T) *_P8File {
	t.Helper()

	var file _P8File

	_Load(
		t,
		VECTOR_PDVS,
		&file,
	)

	return &file
}

// _P8Check compares an encoding with the answer of the oracles. It reuses the check of the
// previous phase, which knows the sha256 rows of a long value.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Check(
	t *testing.T,
	row *_P8Row,
	aligned bool,
	got []byte,
) {
	t.Helper()

	_P7Check(
		t,
		&_P7Row{
			Aper:       row.Aper,
			Uper:       row.Uper,
			AperSha256: row.AperSha256,
			UperSha256: row.UperSha256,
			AperOctets: row.AperOctets,
			UperOctets: row.UperOctets,
		},
		aligned,
		got,
	)
}

// _P8Octets makes the octets that a data spec of the file describes: a hex text, or a count
// of octets by the rule of the vectors of the earlier phases.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Octets(
	t *testing.T,
	spec *_P8Data,
) []byte {
	t.Helper()

	if spec == nil {
		t.Fatalf("row has no data")
	}

	if spec.Hex != nil {
		return _Unhex(
			t,
			*spec.Hex,
		)
	}

	return _FragmentOctets(*spec.Count)
}

// _P8Arcs turns the arcs of the file into an object identifier.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Arcs(arcs []int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(slices.Clone(arcs))
}

// _P8Bits makes the arbitrary BIT STRING of count bits by the rule of pdvs.py.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Bits(count int) asn1.BitString {
	bits := asn1.BitString{
		Bytes: make(
			[]byte,
			(count+7)/8,
		),
		BitLength: count,
	}

	for index := range count {
		if (index*P8_BIT_MULTIPLIER+P8_BIT_OFFSET)%P8_BIT_MODULUS < P8_BIT_LIMIT {
			bits.Bytes[index/8] |= 0x80 >> (index % 8)
		}
	}

	return bits
}

// _P8Identification builds the identification that a row describes.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Identification(
	t *testing.T,
	ident *_P8Ident,
) *per.Identification {
	t.Helper()

	switch ident.Alt {
	case P8_SYNTAXES:
		return &per.Identification{
			Choices: &per.Identification_Syntaxes{
				Abstract: _P8Arcs(ident.Abstract),
				Transfer: _P8Arcs(ident.Transfer),
			},
		}
	case P8_SYNTAX:
		syntax := per.Identification_Syntax(_P8Arcs(ident.OID))

		return &per.Identification{
			Choices: &syntax,
		}
	case P8_PRESENTATION_CONTEXT_ID:
		id := per.Identification_PresentationContextId(ident.ID)

		return &per.Identification{
			Choices: &id,
		}
	case P8_CONTEXT_NEGOTIATION:
		return &per.Identification{
			Choices: &per.Identification_ContextNegotiation{
				PresentationContextId: ident.ID,
				TransferSyntax:        _P8Arcs(ident.OID),
			},
		}
	case P8_TRANSFER_SYNTAX:
		syntax := per.Identification_TransferSyntax(_P8Arcs(ident.OID))

		return &per.Identification{
			Choices: &syntax,
		}
	case P8_FIXED:
		return &per.Identification{
			Choices: &per.Identification_Fixed{},
		}
	}

	t.Fatalf(
		"unknown identification %q",
		ident.Alt,
	)

	return nil
}

// _P8Encoding builds the encoding CHOICE of an EXTERNAL row. The payload of a
// single-ASN1-type is the inner octets of the file: the complete encoding of a small type, or
// the octets of a data spec.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Encoding(
	t *testing.T,
	spec *_P8EncodingRow,
) *per.ExternalEncoding {
	t.Helper()

	switch spec.Alt {
	case P8_SINGLE_ASN1_TYPE:
		inner := per.ExternalEncoding_SingleASN1Type(_P8Inner(
			t,
			spec.Inner,
			spec.Data,
		))

		return &per.ExternalEncoding{
			Choices: &inner,
		}
	case P8_OCTET_ALIGNED:
		octets := per.ExternalEncoding_OctetAligned(_P8Octets(
			t,
			spec.Data,
		))

		return &per.ExternalEncoding{
			Choices: &octets,
		}
	case P8_ARBITRARY:
		bits := per.ExternalEncoding_Arbitrary(_P8Bits(spec.Bits))

		return &per.ExternalEncoding{
			Choices: &bits,
		}
	}

	t.Fatalf(
		"unknown encoding %q",
		spec.Alt,
	)

	return nil
}

// _P8Inner returns the inner octets of an open type: the hex text of the file, or the octets
// of a data spec.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Inner(
	t *testing.T,
	inner *string,
	spec *_P8Data,
) []byte {
	t.Helper()

	if inner != nil {
		return _Unhex(
			t,
			*inner,
		)
	}

	return _P8Octets(
		t,
		spec,
	)
}

// _P8External builds the EXTERNAL value of a row.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8External(
	t *testing.T,
	row *_P8Row,
) *per.External {
	t.Helper()

	value := &per.External{
		DataValueDescriptor: row.Descriptor,
		Encoding: _P8Encoding(
			t,
			row.Encoding,
		),
	}

	if row.Identification != nil {
		value.Identification = _P8Identification(
			t,
			row.Identification,
		)
	}

	return value
}

// _P8Instance builds the INSTANCE OF value of a row.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Instance(
	t *testing.T,
	row *_P8Row,
) *per.InstanceOf {
	t.Helper()

	return &per.InstanceOf{
		TypeID: _P8Arcs(row.TypeID),
		Value: _P8Inner(
			t,
			row.Inner,
			row.Data,
		),
	}
}

// _P8Name names a row for a subtest.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Name(
	row *_P8Row,
	index int,
) string {
	name := fmt.Sprintf(
		"%s_%d",
		row.Type,
		index,
	)

	if row.Identification != nil {
		name += "_" + row.Identification.Alt
	}

	if row.Encoding != nil {
		name += "_" + row.Encoding.Alt
	}

	return name
}

// _P8SameIdentification reports a decoded identification that differs from the one written. It
// compares the alternative by its kind (the CHOICE index of X.691 23.2) and then its fields.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8SameIdentification(
	t *testing.T,
	got,
	want *per.Identification,
) {
	t.Helper()

	if got == nil || got.Choices == nil {
		t.Fatalf(
			"decoded identification is empty: %v",
			got,
		)
	}

	if got.Choices.Kind() != want.Choices.Kind() {
		t.Fatalf(
			"decoded identification kind %d, want %d",
			got.Choices.Kind(),
			want.Choices.Kind(),
		)
	}

	if !_P8EqualChoice(
		got.Choices,
		want.Choices,
	) {
		t.Fatalf(
			"decoded identification %+v, want %+v",
			got.Choices,
			want.Choices,
		)
	}
}

// _P8EqualChoice compares two alternatives of the same kind.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8EqualChoice(
	got,
	want any,
) bool {
	switch want := want.(type) {
	case *per.Identification_Syntaxes:
		have := got.(*per.Identification_Syntaxes)

		return slices.Equal(
			have.Abstract,
			want.Abstract,
		) && slices.Equal(
			have.Transfer,
			want.Transfer,
		)
	case *per.Identification_Syntax:
		return slices.Equal(
			*got.(*per.Identification_Syntax),
			*want,
		)
	case *per.Identification_PresentationContextId:
		return *got.(*per.Identification_PresentationContextId) == *want
	case *per.Identification_ContextNegotiation:
		have := got.(*per.Identification_ContextNegotiation)

		return have.PresentationContextId == want.PresentationContextId &&
			slices.Equal(
				have.TransferSyntax,
				want.TransferSyntax,
			)
	case *per.Identification_TransferSyntax:
		return slices.Equal(
			*got.(*per.Identification_TransferSyntax),
			*want,
		)
	}

	return true
}

// _P8SameEncoding reports a decoded EXTERNAL encoding that differs from the one written.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8SameEncoding(
	t *testing.T,
	got,
	want *per.ExternalEncoding,
) {
	t.Helper()

	if got == nil || got.Choices == nil {
		t.Fatalf(
			"decoded encoding is empty: %v",
			got,
		)
	}

	if got.Choices.Kind() != want.Choices.Kind() {
		t.Fatalf(
			"decoded encoding kind %d, want %d",
			got.Choices.Kind(),
			want.Choices.Kind(),
		)
	}

	switch want := want.Choices.(type) {
	case *per.ExternalEncoding_SingleASN1Type:
		_P8SameOctets(
			t,
			*got.Choices.(*per.ExternalEncoding_SingleASN1Type),
			*want,
		)
	case *per.ExternalEncoding_OctetAligned:
		_P8SameOctets(
			t,
			*got.Choices.(*per.ExternalEncoding_OctetAligned),
			*want,
		)
	case *per.ExternalEncoding_Arbitrary:
		have := got.Choices.(*per.ExternalEncoding_Arbitrary)

		if have.BitLength != want.BitLength || !bytes.Equal(
			have.Bytes,
			want.Bytes,
		) {
			t.Fatalf(
				"decoded %d bits % x, want %d bits % x",
				have.BitLength,
				have.Bytes,
				want.BitLength,
				want.Bytes,
			)
		}
	}
}

// _P8SameOctets reports decoded octets that differ from the ones written. An empty slice and
// a nil slice are the same value.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8SameOctets(
	t *testing.T,
	got,
	want []byte,
) {
	t.Helper()

	if !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"decoded %d octets, want %d (first difference at %d)",
			len(got),
			len(want),
			_P8Difference(
				got,
				want,
			),
		)
	}
}

// _P8Difference returns the index of the first octet where two slices differ.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Difference(
	left,
	right []byte,
) int {
	for index := range min(
		len(left),
		len(right),
	) {
		if left[index] != right[index] {
			return index
		}
	}

	return min(
		len(left),
		len(right),
	)
}

// _P8SameExternal reports a decoded EXTERNAL that differs from the one written.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8SameExternal(
	t *testing.T,
	got,
	want *per.External,
) {
	t.Helper()

	if got == nil {
		t.Fatalf("decoded EXTERNAL is nil")
	}

	_P8SameIdentification(
		t,
		got.Identification,
		want.Identification,
	)

	_P8SameEncoding(
		t,
		got.Encoding,
		want.Encoding,
	)

	if (got.DataValueDescriptor == nil) != (want.DataValueDescriptor == nil) {
		t.Fatalf(
			"descriptor present %v, want %v",
			got.DataValueDescriptor != nil,
			want.DataValueDescriptor != nil,
		)
	}

	if want.DataValueDescriptor == nil {
		return
	}

	if *got.DataValueDescriptor != *want.DataValueDescriptor {
		t.Fatalf(
			"descriptor %q, want %q",
			*got.DataValueDescriptor,
			*want.DataValueDescriptor,
		)
	}
}

// _P8Rows returns the rows of a kind that hold their octets, which excludes the sha256 rows of
// a long value.
//
// Revisions:
//   - 2026-10-19 15:13: initial creation
func _P8Rows(rows []*_P8Row) []*_P8Row {
	var out []*_P8Row

	for _, row := range rows {
		if row.Aper != "" {
			out = append(
				out,
				row,
			)
		}
	}

	return out
}
