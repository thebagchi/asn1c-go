package per_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// The three modes of a component of a SEQUENCE or SET.
const (
	P7_REQUIRED = iota
	P7_OPTIONAL
	P7_DEFAULT
)

// _P7Field is one component of a hand-written SEQUENCE or SET codec: the
// description that generated code has built into its statements.
type _P7Field struct {
	name string
	kind string
	mode int
	def  any
}

// _P7Addition is one extension addition: a single component, or a group
// [[ ... ]] that is encoded as a SEQUENCE inside the open type (X.691 19.9).
type _P7Addition struct {
	group  bool
	fields []*_P7Field
}

// _P7Sequence describes a SEQUENCE or SET type. fields is the order of encoding:
// the textual order for a SEQUENCE, the canonical order of its tags for a SET
// (X.691 21), the root components after a second extension marker moved before
// the additions (X.691 19.9 note 2). preamble, when given, is the order of the
// marked components in the preamble bits when it differs from the order of fields
// (TestSet_PreambleOrder uses it for the textual order of the oracles).
type _P7Sequence struct {
	fields     []*_P7Field
	preamble   []*_P7Field
	additions  []*_P7Addition
	extensible bool
}

// _P7Required describes a component with no OPTIONAL or DEFAULT.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Required(
	name,
	kind string,
) *_P7Field {
	return &_P7Field{
		name: name,
		kind: kind,
		mode: P7_REQUIRED,
	}
}

// _P7Optional describes a component marked OPTIONAL.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Optional(
	name,
	kind string,
) *_P7Field {
	return &_P7Field{
		name: name,
		kind: kind,
		mode: P7_OPTIONAL,
	}
}

// _P7Default describes a component marked DEFAULT.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Default(
	name,
	kind string,
	def any,
) *_P7Field {
	return &_P7Field{
		name: name,
		kind: kind,
		mode: P7_DEFAULT,
		def:  def,
	}
}

// _P7Single describes an extension addition that is one component.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Single(
	name,
	kind string,
) *_P7Addition {
	return &_P7Addition{
		fields: []*_P7Field{_P7Optional(
			name,
			kind,
		)},
	}
}

// _P7Group describes an extension addition group.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Group(fields ...*_P7Field) *_P7Addition {
	return &_P7Addition{
		group:  true,
		fields: fields,
	}
}

// The two marked components of Set2, which the type and its preamble share.
var (
	P7_SET2_D = _P7Optional(
		"d",
		P7_BOOL,
	)
	P7_SET2_E = _P7Default(
		"e",
		P7_BOOL,
		false,
	)
)

// P7_SEQUENCES holds the SEQUENCE and SET types of testing.asn1.
var (
	P7_SEQUENCES = map[string]*_P7Sequence{
		"Opt": {
			fields: []*_P7Field{
				_P7Optional(
					"a",
					P7_BOOL,
				),
				_P7Default(
					"b",
					P7_INT,
					int64(7),
				),
				_P7Optional(
					"c",
					P7_STR,
				),
				_P7Default(
					"d",
					P7_BOOL,
					true,
				),
				_P7Required(
					"e",
					P7_INT,
				),
			},
		},
		"OptSent": {
			fields: []*_P7Field{
				_P7Optional(
					"a",
					P7_BOOL,
				),
				_P7Optional(
					"b",
					P7_INT,
				),
				_P7Optional(
					"c",
					P7_STR,
				),
				_P7Optional(
					"d",
					P7_BOOL,
				),
				_P7Required(
					"e",
					P7_INT,
				),
			},
		},
		"Empty": {},
		"EmptyExt": {
			extensible: true,
		},
		"ExtBig": _P7Big(70),
		"Ext1": {
			extensible: true,
			fields: []*_P7Field{
				_P7Required(
					"a",
					P7_BOOL,
				),
				_P7Optional(
					"b",
					P7_INT,
				),
			},
			additions: []*_P7Addition{
				_P7Single(
					"c",
					P7_INT,
				),
			},
		},
		// ExtT1 has a root component t after the second extension marker. X.691 19.9
		// note 2 encodes it as if it stood before the marker, so before the additions.
		"ExtT1": {
			extensible: true,
			fields: []*_P7Field{
				_P7Required(
					"a",
					P7_BOOL,
				),
				_P7Optional(
					"b",
					P7_INT,
				),
				_P7Required(
					"t",
					P7_INT,
				),
			},
			additions: []*_P7Addition{
				_P7Single(
					"c",
					P7_INT,
				),
			},
		},
		"Ext2": {
			extensible: true,
			fields: []*_P7Field{
				_P7Required(
					"a",
					P7_BOOL,
				),
				_P7Optional(
					"b",
					P7_INT,
				),
			},
			additions: []*_P7Addition{
				_P7Single(
					"c",
					P7_INT,
				),
				_P7Single(
					"d",
					P7_STR,
				),
				_P7Single(
					"g",
					P7_BOOL,
				),
				_P7Group(
					_P7Required(
						"e",
						P7_BOOL,
					),
					_P7Optional(
						"f",
						P7_INT,
					),
				),
			},
		},
		"ExtN": {
			extensible: true,
			fields: []*_P7Field{
				_P7Required(
					"a",
					P7_BOOL,
				),
			},
			additions: []*_P7Addition{
				_P7Single(
					"n",
					P7_NULL,
				),
			},
		},
		"Set1": {
			fields: []*_P7Field{
				_P7Required(
					"a",
					P7_BOOL,
				),
				_P7Optional(
					"b",
					P7_INT,
				),
				_P7Required(
					"c",
					P7_STR,
				),
			},
		},
		// Set2 sorts by tag class and number (X.680 8.6): c [APPLICATION 1], b [0],
		// e [1], a [2], d [PRIVATE 0]. The preamble bits follow that order
		// too, e then d (X.691 21, user decision 2026-10-19).
		"Set2": {
			fields: []*_P7Field{
				_P7Required(
					"c",
					P7_STR,
				),
				_P7Required(
					"b",
					P7_INT,
				),
				P7_SET2_E,
				_P7Required(
					"a",
					P7_BOOL,
				),
				P7_SET2_D,
			},
		},
	}
)

// _P7Present reports whether a component has an encoding: an OPTIONAL one that
// has a value, a DEFAULT one whose value differs from its default (X.691 19.5:
// for BASIC-PER a DEFAULT of a simple type is absent when it equals its
// default), and every component that is not marked.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Present(
	field *_P7Field,
	value map[string]any,
) bool {
	item, ok := value[field.name]

	switch field.mode {
	case P7_REQUIRED:
		return true
	case P7_DEFAULT:
		return ok && item != field.def
	}

	return ok
}

// _P7Marked returns the components that have a bit in the preamble, in the order
// of the bits: the order given, or else the order of the fields.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Marked(
	fields,
	order []*_P7Field,
) []*_P7Field {
	if order != nil {
		return order
	}

	var marked []*_P7Field

	for _, field := range fields {
		if field.mode != P7_REQUIRED {
			marked = append(
				marked,
				field,
			)
		}
	}

	return marked
}

// _P7EncodeFields writes the preamble and the components of a SEQUENCE, SET or
// addition group (X.691 19.2 to 19.4). The bits follow order when it is given.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
//   - 2026-10-19 14:18: takes the order of the preamble bits
func _P7EncodeFields(
	enc *per.Encoder,
	fields,
	order []*_P7Field,
	value map[string]any,
) error {
	var (
		marked = _P7Marked(
			fields,
			order,
		)
		bits = _P7Bits(len(marked))
	)

	for index, field := range marked {
		if _P7Present(
			field,
			value,
		) {
			_P7Mark(
				bits,
				index,
			)
		}
	}

	if err := enc.EncodePreamble(bits); err != nil {
		return err
	}

	for _, field := range fields {
		if !_P7Present(
			field,
			value,
		) {
			continue
		}

		if err := _P7WriteScalar(
			enc,
			field.kind,
			value[field.name],
		); err != nil {
			return err
		}
	}

	return nil
}

// _P7DecodeFields reads what _P7EncodeFields wrote. A DEFAULT component that is
// absent gets its default.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
//   - 2026-10-19 14:18: takes the order of the preamble bits
func _P7DecodeFields(
	dec *per.Decoder,
	fields,
	order []*_P7Field,
	value map[string]any,
) error {
	var (
		marked = _P7Marked(
			fields,
			order,
		)
		bits = _P7Bits(len(marked))
	)

	if err := dec.DecodePreamble(bits); err != nil {
		return err
	}

	for _, field := range fields {
		present := field.mode == P7_REQUIRED

		for index, item := range marked {
			if item == field {
				present = bits.At(index) == 1
			}
		}

		if !present {
			if field.mode == P7_DEFAULT {
				value[field.name] = field.def
			}

			continue
		}

		item, err := _P7ReadScalar(
			dec,
			field.kind,
		)
		if err != nil {
			return err
		}

		value[field.name] = item
	}

	return nil
}

// _P7Additions counts the extension additions of a type that have a value.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Additions(
	seq *_P7Sequence,
	value map[string]any,
) int {
	count := 0

	for _, addition := range seq.additions {
		if _, ok := value[addition.fields[0].name]; ok {
			count++
		}
	}

	return count
}

// _P7EncodeSequence writes a SEQUENCE or SET value: the extension bit, the root
// (X.691 19.1 to 19.4), and when an addition has a value the bitmap of 19.7 and
// 19.8 and every present addition as an open type (19.9).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7EncodeSequence(
	enc *per.Encoder,
	seq *_P7Sequence,
	value map[string]any,
) error {
	var (
		bits = _P7Bits(len(seq.additions))
		used = _P7Additions(
			seq,
			value,
		) > 0
	)

	for index, addition := range seq.additions {
		if _, ok := value[addition.fields[0].name]; ok {
			_P7Mark(
				bits,
				index,
			)
		}
	}

	if seq.extensible {
		if err := enc.WriteExtensionBit(used); err != nil {
			return err
		}
	}

	if err := _P7EncodeFields(
		enc,
		seq.fields,
		seq.preamble,
		value,
	); err != nil {
		return err
	}

	if !used {
		return nil
	}

	if err := enc.EncodeAdditions(bits); err != nil {
		return err
	}

	return _P7EncodeAdditions(
		enc,
		seq,
		value,
	)
}

// _P7EncodeAdditions writes each present addition as an open type.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7EncodeAdditions(
	enc *per.Encoder,
	seq *_P7Sequence,
	value map[string]any,
) error {
	for _, addition := range seq.additions {
		first := addition.fields[0]
		if _, ok := value[first.name]; !ok {
			continue
		}

		inner := enc.Nested()

		if err := _P7EncodeAddition(
			inner,
			addition,
			value,
		); err != nil {
			return err
		}

		if err := enc.EncodeOpenType(inner.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

// _P7EncodeAddition writes the inner value of an addition: a component as its
// type, a group as a SEQUENCE with its own preamble (X.691 19.9).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7EncodeAddition(
	inner *per.Encoder,
	addition *_P7Addition,
	value map[string]any,
) error {
	if addition.group {
		return _P7EncodeFields(
			inner,
			addition.fields,
			nil,
			value,
		)
	}

	return _P7WriteScalar(
		inner,
		addition.fields[0].kind,
		value[addition.fields[0].name],
	)
}

// _P7DecodeSequence reads a value written by _P7EncodeSequence of this version or
// of a later one. It returns the value and the number of additions it does not
// know, which it has skipped (X.691 19.7 note, 11.2).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7DecodeSequence(
	dec *per.Decoder,
	seq *_P7Sequence,
) (map[string]any, uint64, error) {
	var (
		value = map[string]any{}
		used  = false
	)

	if seq.extensible {
		var err error

		used, err = dec.ReadExtensionBit()
		if err != nil {
			return nil, 0, err
		}
	}

	if err := _P7DecodeFields(
		dec,
		seq.fields,
		seq.preamble,
		value,
	); err != nil {
		return nil, 0, err
	}

	if !used {
		return value, 0, nil
	}

	var (
		bits = _P7Bits(len(seq.additions))

		unknown, err = dec.DecodeAdditions(bits)
	)
	if err != nil {
		return nil, 0, err
	}

	for index, addition := range seq.additions {
		if bits.At(index) == 0 {
			continue
		}

		if err := _P7DecodeAddition(
			dec,
			addition,
			value,
		); err != nil {
			return nil, 0, err
		}
	}

	return value, unknown, dec.SkipOpenTypes(unknown)
}

// _P7DecodeAddition reads one present addition from its open type.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7DecodeAddition(
	dec *per.Decoder,
	addition *_P7Addition,
	value map[string]any,
) error {
	data, err := dec.DecodeOpenType()
	if err != nil {
		return err
	}

	inner := DECODERS[dec.Aligned()](data)

	if addition.group {
		return _P7DecodeFields(
			inner,
			addition.fields,
			nil,
			value,
		)
	}

	item, err := _P7ReadScalar(
		inner,
		addition.fields[0].kind,
	)
	if err != nil {
		return err
	}

	value[addition.fields[0].name] = item

	return nil
}

// _P7Kinds maps every name of a SEQUENCE to the kind of its component.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Kinds(seq *_P7Sequence) map[string]string {
	kinds := map[string]string{}

	for _, field := range seq.fields {
		kinds[field.name] = field.kind
	}

	for _, addition := range seq.additions {
		for _, field := range addition.fields {
			kinds[field.name] = field.kind
		}
	}

	return kinds
}

// _P7Parse reads the value of a row into typed Go values.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Parse(
	t *testing.T,
	seq *_P7Sequence,
	raw json.RawMessage,
) map[string]any {
	t.Helper()

	var items map[string]any

	if err := json.Unmarshal(
		raw,
		&items,
	); err != nil {
		t.Fatalf(
			"value %s: %v",
			raw,
			err,
		)
	}

	var (
		kinds = _P7Kinds(seq)
		value = map[string]any{}
	)

	for name, item := range items {
		value[name] = _P7Typed(
			t,
			kinds[name],
			item,
		)
	}

	return value
}

// _P7Normal returns what a decoder of seq gives for value: the components it
// knows, with the default of every DEFAULT component that has no value.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Normal(
	seq *_P7Sequence,
	value map[string]any,
) map[string]any {
	var (
		kinds = _P7Kinds(seq)
		out   = map[string]any{}
	)

	for name, item := range value {
		if _, known := kinds[name]; known {
			out[name] = item
		}
	}

	for _, field := range seq.fields {
		if field.mode == P7_DEFAULT {
			if _, ok := out[field.name]; !ok {
				out[field.name] = field.def
			}
		}
	}

	return out
}

// _P7Equal compares two decoded values.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Equal(
	t *testing.T,
	got,
	want map[string]any,
) {
	t.Helper()

	if !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf(
			"decoded %v, want %v",
			got,
			want,
		)
	}
}

// _P7SequenceVectors checks encode = oracle and decode = value for rows of
// SEQUENCE and SET types, in both variants.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7SequenceVectors(
	t *testing.T,
	rows []*_P7Row,
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for index, row := range rows {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						seq   = P7_SEQUENCES[row.Type]
						value = _P7Parse(
							t,
							seq,
							row.Value,
						)
						enc = ENCODERS[aligned]()
					)

					if err := _P7EncodeSequence(
						enc,
						seq,
						value,
					); err != nil {
						t.Fatalf(
							"encode %s = %v",
							row.Value,
							err,
						)
					}

					_P7Check(
						t,
						row,
						aligned,
						enc.Bytes(),
					)

					got, unknown, err := _P7DecodeSequence(
						DECODERS[aligned](enc.Bytes()),
						seq,
					)
					if err != nil || unknown != 0 {
						t.Fatalf(
							"decode = %v, %d unknown, %v",
							got,
							unknown,
							err,
						)
					}

					_P7Equal(
						t,
						got,
						_P7Normal(
							seq,
							value,
						),
					)
				},
			)
		}
	}
}

// _P7SequenceFramed writes each row between BOOLEAN fields and reads it back.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7SequenceFramed(
	t *testing.T,
	rows []*_P7Row,
) {
	t.Helper()

	for _, aligned := range []bool{true, false} {
		for index, row := range rows {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						seq   = P7_SEQUENCES[row.Type]
						value = _P7Parse(
							t,
							seq,
							row.Value,
						)
					)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return _P7EncodeSequence(
								enc,
								seq,
								value,
							)
						},
						func(dec *per.Decoder) error {
							got, _, err := _P7DecodeSequence(
								dec,
								seq,
							)
							if err == nil {
								_P7Equal(
									t,
									got,
									_P7Normal(
										seq,
										value,
									),
								)
							}

							return err
						},
					)
				},
			)
		}
	}
}

// TestSequence_Vectors checks the SEQUENCE primitives against the octets of
// pycrate and OTP (testing/composites.py) for Opt, which has OPTIONAL and
// DEFAULT components, and for Empty and EmptyExt. The rows cover every presence
// pattern of the four marked components, with each DEFAULT absent, equal to its
// default and different from it. X.691 19.2 puts one preamble bit in front of
// the components for each of them. X.691 19.5: a DEFAULT of a simple type, such as
// BOOLEAN and INTEGER, equal to its default is always absent, in BASIC-PER as in
// CANONICAL-PER, so the hand codec sends no such component and the oracles give
// the same octets. SEQUENCE {} and SEQUENCE { ... } have no component: the
// complete encoding is one octet 00 (11.1.3, 19.1).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestSequence_Vectors(t *testing.T) {
	file := _P7Load(t)

	_P7SequenceVectors(
		t,
		_P7Of(
			file.Sequence,
			"Opt",
			"Empty",
			"EmptyExt",
		),
	)
}

// TestSequence_Framed writes the rows of Opt, Empty and EmptyExt between BOOLEAN
// fields, so that a preamble of the wrong width (X.691 19.2) shows in the field
// that follows.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestSequence_Framed(t *testing.T) {
	file := _P7Load(t)

	_P7SequenceFramed(
		t,
		_P7Of(
			file.Sequence,
			"Opt",
			"Empty",
			"EmptyExt",
		),
	)
}

// TestSequence_DefaultSent checks the decoder side of X.691 19.5. A sender may
// not send a DEFAULT of a simple type that equals its default, but a decoder
// that meets one reads it: the rows of OptSent have the bits of Opt with b and d
// sent, whatever their value. Opt decodes them to the same value as the row, and
// for a value equal to the default the encoding of Opt (canonical, absent) is
// shorter than the one of OptSent.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestSequence_DefaultSent(t *testing.T) {
	var (
		file      = _P7Load(t)
		canonical = map[string]*_P7Row{}
	)

	for _, row := range _P7Of(
		file.Sequence,
		"Opt",
	) {
		canonical[string(row.Value)] = row
	}

	var (
		opt     = P7_SEQUENCES["Opt"]
		shorter = 0
	)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P7Of(
			file.Sequence,
			"OptSent",
		) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						value = _P7Parse(
							t,
							P7_SEQUENCES["OptSent"],
							row.Value,
						)
						want = _P7Want(
							row,
							aligned,
						)

						got, unknown, err = _P7DecodeSequence(
							DECODERS[aligned](_Unhex(
								t,
								want.hex,
							)),
							opt,
						)
					)
					if err != nil || unknown != 0 {
						t.Fatalf(
							"decode = %v, %d unknown, %v",
							got,
							unknown,
							err,
						)
					}

					_P7Equal(
						t,
						got,
						_P7Normal(
							opt,
							value,
						),
					)
				},
			)

			if len(_P7Want(
				canonical[string(row.Value)],
				aligned,
			).hex) <
				len(_P7Want(
					row,
					aligned,
				).hex) {
				shorter++
			}
		}
	}

	if shorter == 0 {
		t.Fatalf("no value equal to its DEFAULT is shorter in Opt than in OptSent")
	}
}

// TestSet_Vectors checks SET against the octets of the oracles. Set1 has context
// tags in textual order. Set2 has tags that sort to c [APPLICATION 1], b [0], e
// [1], a [2], d [PRIVATE 0]: X.691 21 encodes the components in that order. The
// hand codec writes them in that order and uses no further primitive. The
// preamble bits follow the same sorted order (e, then d), because X.691 21 encodes
// the sorted elements "as if it had been declared a sequence type" (user decision
// 2026-10-19). The expected octets are the answers of pycrate and OTP for Set1Seq
// and Set2Seq, SEQUENCE types with the same components and tags declared in that
// order. The oracles' own answers for the SETs keep the preamble in textual order;
// the rows hold them as set_oracle, a record that TestSet_PreambleOrder checks.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
//   - 2026-10-19 14:27: expected octets from the SEQUENCE in sorted order
func TestSet_Vectors(t *testing.T) {
	file := _P7Load(t)

	_P7SequenceVectors(
		t,
		file.Set,
	)
}

// TestSet_Framed writes the rows of Set1 and Set2 between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestSet_Framed(t *testing.T) {
	file := _P7Load(t)

	_P7SequenceFramed(
		t,
		file.Set,
	)
}

// TestSet_TextualOrderDiffers checks that the rows of Set2 tell the canonical
// order from the textual one: with the components written in the order of the
// text, at least one row (and in practice every one) gives other octets than the
// oracles. A test that passed with either order would not test X.691 21.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestSet_TextualOrderDiffers(t *testing.T) {
	var (
		file      = _P7Load(t)
		canonical = P7_SEQUENCES["Set2"]
		textual   = &_P7Sequence{
			fields: []*_P7Field{
				canonical.fields[3],
				canonical.fields[1],
				canonical.fields[0],
				canonical.fields[4],
				canonical.fields[2],
			},
		}
		differs = 0
		rows    = _P7Of(
			file.Set,
			"Set2",
		)
	)

	for _, row := range rows {
		enc := per.NewUnalignedEncoder()

		if err := _P7EncodeSequence(
			enc,
			textual,
			_P7Parse(
				t,
				canonical,
				row.Value,
			),
		); err != nil {
			t.Fatalf(
				"encode = %v",
				err,
			)
		}

		if fmt.Sprintf(
			"%x",
			enc.Bytes(),
		) != row.Uper {
			differs++
		}
	}

	if differs == 0 || differs != len(rows) {
		t.Fatalf(
			"textual order differs on %d of %d rows",
			differs,
			len(rows),
		)
	}
}

// TestSet_PreambleOrder checks the order of the preamble bits of a SET: the sorted
// order of X.691 21 (e, then d in Set2), which the expected octets hold. As a
// record, the textual order that pycrate and OTP give for the SET (the answers in
// the row) is also checked: with the bits in textual order Set2 gives exactly the
// octets of the answer of pycrate in the row, which differ from the expected ones for the
// rows in which e and d are not both absent or both present.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
//   - 2026-10-19 14:27: asserts the sorted order; the oracle SET answer is the record
//   - 2026-10-20 00:51: the oracle SET answer is the py answer of the row
func TestSet_PreambleOrder(t *testing.T) {
	var (
		file      = _P7Load(t)
		canonical = P7_SEQUENCES["Set2"]
		textual   = &_P7Sequence{
			fields: canonical.fields,
			preamble: []*_P7Field{
				P7_SET2_D,
				P7_SET2_E,
			},
		}
		differs = 0
	)

	for _, row := range _P7Of(
		file.Set,
		"Set2",
	) {
		value := _P7Parse(
			t,
			canonical,
			row.Value,
		)

		for seq, want := range map[*_P7Sequence]string{
			canonical: row.Uper,
			textual:   _P7Hex(row.Answers.Uper.Py),
		} {
			enc := per.NewUnalignedEncoder()
			if err := _P7EncodeSequence(
				enc,
				seq,
				value,
			); err != nil {
				t.Fatalf(
					"encode = %v",
					err,
				)
			}

			if got := fmt.Sprintf(
				"%x",
				enc.Bytes(),
			); got != want {
				t.Fatalf(
					"%s: %s, want %s",
					row.Value,
					got,
					want,
				)
			}
		}

		if row.Uper != _P7Hex(row.Answers.Uper.Py) {
			differs++
		}
	}

	if differs == 0 {
		t.Fatalf("the oracle SET answers equal the sorted order on every row")
	}
}

// _P7Big describes ExtBig of testing.asn1: a root BOOLEAN a and count
// extension additions x1 to xN of type BOOLEAN OPTIONAL.
//
// Revisions:
//   - 2026-10-19 14:53: initial creation
func _P7Big(count int) *_P7Sequence {
	seq := &_P7Sequence{
		extensible: true,
		fields: []*_P7Field{
			_P7Required(
				"a",
				P7_BOOL,
			),
		},
	}

	for index := 1; index <= count; index++ {
		seq.additions = append(
			seq.additions,
			_P7Single(
				fmt.Sprintf(
					"x%d",
					index,
				),
				P7_BOOL,
			),
		)
	}

	return seq
}
