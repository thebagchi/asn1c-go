package per_test

import (
	"encoding/json"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// How a decoder treats an extension alternative it does not know: it keeps the
// open type (DecodeOpenType), or it skips it (SkipOpenTypes).
const (
	P7_KEEP = iota
	P7_SKIP
)

type _P7Alternative struct {
	name string
	kind string
}

// _P7Choice describes a CHOICE type: the alternatives of the root and of the
// extension additions, each numbered from 0 (X.691 23.2).
type _P7Choice struct {
	root       []*_P7Alternative
	extensions []*_P7Alternative
	extensible bool
}

// _P7Chosen is what a decoder returns: a known alternative and its value, or the
// index of an unknown extension alternative with the octets of its open type
// (nil when they were skipped).
type _P7Chosen struct {
	name    string
	value   any
	unknown int64
	raw     []byte
}

// _P7Alt describes one alternative.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Alt(
	name,
	kind string,
) *_P7Alternative {
	return &_P7Alternative{
		name: name,
		kind: kind,
	}
}

// P7_CHOICES holds the CHOICE types of testing.asn1.
var (
	P7_CHOICES = map[string]*_P7Choice{
		"Ch1": {
			root: []*_P7Alternative{
				_P7Alt(
					"a",
					P7_INT,
				),
			},
		},
		"Ch2": {
			root: []*_P7Alternative{
				_P7Alt(
					"a",
					P7_BOOL,
				),
				_P7Alt(
					"b",
					P7_INT,
				),
			},
		},
		"Ch3": {
			root: []*_P7Alternative{
				_P7Alt(
					"a",
					P7_BOOL,
				),
				_P7Alt(
					"b",
					P7_INT,
				),
				_P7Alt(
					"c",
					P7_STR,
				),
			},
		},
		"Ch5": {
			root: []*_P7Alternative{
				_P7Alt(
					"a",
					P7_BOOL,
				),
				_P7Alt(
					"b",
					P7_INT,
				),
				_P7Alt(
					"c",
					P7_STR,
				),
				_P7Alt(
					"d",
					P7_BOOL,
				),
				_P7Alt(
					"e",
					P7_INT,
				),
			},
		},
		"ChExt1": {
			extensible: true,
			root: []*_P7Alternative{
				_P7Alt(
					"a",
					P7_BOOL,
				),
				_P7Alt(
					"b",
					P7_INT,
				),
			},
			extensions: []*_P7Alternative{
				_P7Alt(
					"c",
					P7_STR,
				),
			},
		},
		"ChExt2": {
			extensible: true,
			root: []*_P7Alternative{
				_P7Alt(
					"a",
					P7_BOOL,
				),
				_P7Alt(
					"b",
					P7_INT,
				),
			},
			extensions: []*_P7Alternative{
				_P7Alt(
					"c",
					P7_STR,
				),
				_P7Alt(
					"d",
					P7_BOOL,
				),
				_P7Alt(
					"e",
					P7_INT,
				),
			},
		},
	}
)

// _P7Find returns the index of an alternative and whether it is an extension
// addition.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Find(
	choice *_P7Choice,
	name string,
) (int64, bool, *_P7Alternative) {
	for index, alt := range choice.root {
		if alt.name == name {
			return int64(index), false, alt
		}
	}

	for index, alt := range choice.extensions {
		if alt.name == name {
			return int64(index), true, alt
		}
	}

	return -1, false, nil
}

// _P7EncodeChoice writes the extension bit (23.5), the index (23.6 to 23.8; no
// index for a type with one alternative, 23.4) and the alternative, an extension
// alternative as an open type (23.8, 11.2).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7EncodeChoice(
	enc *per.Encoder,
	choice *_P7Choice,
	chosen *_P7Chosen,
) error {
	index, extended, alt := _P7Find(
		choice,
		chosen.name,
	)

	if choice.extensible {
		if err := enc.WriteExtensionBit(extended); err != nil {
			return err
		}
	}

	if !extended {
		if err := enc.EncodeChoiceId(
			index,
			per.Constrained(
				0,
				int64(len(choice.root))-1,
			),
		); err != nil {
			return err
		}

		return _P7WriteScalar(
			enc,
			alt.kind,
			chosen.value,
		)
	}

	if err := enc.EncodeChoiceExtensionId(index); err != nil {
		return err
	}

	inner := enc.Nested()
	if err := _P7WriteScalar(
		inner,
		alt.kind,
		chosen.value,
	); err != nil {
		return err
	}

	return enc.EncodeOpenType(inner.Bytes())
}

// _P7Relay writes an unknown extension alternative the way it came: its index,
// then the octets of its open type.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7Relay(
	enc *per.Encoder,
	chosen *_P7Chosen,
) error {
	if err := enc.WriteExtensionBit(true); err != nil {
		return err
	}

	if err := enc.EncodeChoiceExtensionId(chosen.unknown); err != nil {
		return err
	}

	return enc.EncodeOpenType(chosen.raw)
}

// _P7DecodeChoice reads a CHOICE value. An extension alternative that the type
// does not know is kept or skipped, as mode says.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7DecodeChoice(
	dec *per.Decoder,
	choice *_P7Choice,
	mode int,
) (*_P7Chosen, error) {
	extended := false

	if choice.extensible {
		var err error

		extended, err = dec.ReadExtensionBit()
		if err != nil {
			return nil, err
		}
	}

	if !extended {
		index, err := dec.DecodeChoiceId(per.Constrained(
			0,
			int64(len(choice.root))-1,
		))
		if err != nil {
			return nil, err
		}

		return _P7DecodeAlternative(
			dec,
			choice.root[index],
		)
	}

	index, err := dec.DecodeChoiceExtensionId()
	if err != nil {
		return nil, err
	}

	if index < int64(len(choice.extensions)) {
		data, err := dec.DecodeOpenType()
		if err != nil {
			return nil, err
		}

		return _P7DecodeAlternative(
			DECODERS[dec.Aligned()](data),
			choice.extensions[index],
		)
	}

	chosen := &_P7Chosen{
		unknown: index,
	}

	if mode == P7_SKIP {
		return chosen, dec.SkipOpenTypes(1)
	}

	chosen.raw, err = dec.DecodeOpenType()

	return chosen, err
}

// _P7DecodeAlternative reads the value of a known alternative.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7DecodeAlternative(
	dec *per.Decoder,
	alt *_P7Alternative,
) (*_P7Chosen, error) {
	value, err := _P7ReadScalar(
		dec,
		alt.kind,
	)

	return &_P7Chosen{
		name:    alt.name,
		value:   value,
		unknown: -1,
	}, err
}

// _P7ParseChoice reads the value of a row.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7ParseChoice(
	t *testing.T,
	choice *_P7Choice,
	raw json.RawMessage,
) *_P7Chosen {
	t.Helper()

	var item struct {
		Alt   string `json:"alt"`
		Value any    `json:"value"`
	}

	if err := json.Unmarshal(
		raw,
		&item,
	); err != nil {
		t.Fatalf(
			"value %s: %v",
			raw,
			err,
		)
	}

	_, _, alt := _P7Find(
		choice,
		item.Alt,
	)
	if alt == nil {
		t.Fatalf(
			"no alternative %q",
			item.Alt,
		)
	}

	return &_P7Chosen{
		name: item.Alt,
		value: _P7Typed(
			t,
			alt.kind,
			item.Value,
		),
		unknown: -1,
	}
}

// _P7SameChoice reports a decoded alternative that differs from the wanted one.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7SameChoice(
	t *testing.T,
	got,
	want *_P7Chosen,
) {
	t.Helper()

	if got.name != want.name || got.value != want.value || got.unknown != want.unknown {
		t.Fatalf(
			"decoded %+v, want %+v",
			*got,
			*want,
		)
	}
}

// TestChoice_Vectors checks CHOICE against the octets of pycrate and OTP for
// types of 1, 2, 3 and 5 alternatives, and two extensible ones (ChExt1 with the
// extension alternative c, ChExt2 with c, d and e). X.691 23.6: the index of a
// root alternative is a constrained whole number of 0 to n (EncodeChoiceId), with
// no encoding at all when the root has one alternative (23.4). An extensible
// type puts the extension bit first (23.5); an extension alternative has its index
// as a normally small non-negative whole number and its value as an open type
// (23.8, EncodeChoiceExtensionId, EncodeOpenType).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestChoice_Vectors(t *testing.T) {
	file := _P7Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.Choice {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						choice = P7_CHOICES[row.Type]
						chosen = _P7ParseChoice(
							t,
							choice,
							row.Value,
						)
						enc = ENCODERS[aligned]()
					)

					if err := _P7EncodeChoice(
						enc,
						choice,
						chosen,
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

					got, err := _P7DecodeChoice(
						DECODERS[aligned](enc.Bytes()),
						choice,
						P7_KEEP,
					)
					if err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					_P7SameChoice(
						t,
						got,
						chosen,
					)
				},
			)
		}
	}
}

// TestChoice_Framed writes the rows between BOOLEAN fields.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestChoice_Framed(t *testing.T) {
	file := _P7Load(t)

	for _, aligned := range []bool{true, false} {
		for index, row := range file.Choice {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						choice = P7_CHOICES[row.Type]
						chosen = _P7ParseChoice(
							t,
							choice,
							row.Value,
						)
					)

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return _P7EncodeChoice(
								enc,
								choice,
								chosen,
							)
						},
						func(dec *per.Decoder) error {
							got, err := _P7DecodeChoice(
								dec,
								choice,
								P7_KEEP,
							)
							if err == nil {
								_P7SameChoice(
									t,
									got,
									chosen,
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

// TestChoice_UnknownAlternative decodes the encodings of ChExt2 with the codec
// of ChExt1, which knows the extension alternative c only. For d and e,
// DecodeChoiceExtensionId gives the index 1 or 2 and the codec either keeps the
// open type with DecodeOpenType and writes it again unchanged (the octets are
// the ones of the oracles), or skips it with SkipOpenTypes; the BOOLEAN after the
// value is read correctly (X.691 23.8, 11.2). The other alternatives decode to
// their value.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestChoice_UnknownAlternative(t *testing.T) {
	var (
		file    = _P7Load(t)
		newer   = P7_CHOICES["ChExt2"]
		older   = P7_CHOICES["ChExt1"]
		unknown = 0
	)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P7Of(
			file.Choice,
			"ChExt2",
		) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					var (
						chosen = _P7ParseChoice(
							t,
							newer,
							row.Value,
						)
						want = chosen
					)

					if _, _, alt := _P7Find(
						older,
						chosen.name,
					); alt == nil {
						position, _, _ := _P7Find(
							newer,
							chosen.name,
						)
						want = &_P7Chosen{
							unknown: position,
						}
						unknown++
					}

					got, err := _P7DecodeChoice(
						DECODERS[aligned](_Unhex(
							t,
							_P7Want(
								row,
								aligned,
							).hex,
						)),
						older,
						P7_KEEP,
					)
					if err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					_P7SameChoice(
						t,
						got,
						want,
					)

					if got.unknown >= 0 {
						enc := ENCODERS[aligned]()

						if err := _P7Relay(
							enc,
							got,
						); err != nil {
							t.Fatalf(
								"relay = %v",
								err,
							)
						}

						_P7Check(
							t,
							row,
							aligned,
							enc.Bytes(),
						)
					}

					_CheckFramed(
						t,
						aligned,
						func(enc *per.Encoder) error {
							return _P7EncodeChoice(
								enc,
								newer,
								chosen,
							)
						},
						func(dec *per.Decoder) error {
							skipped, err := _P7DecodeChoice(
								dec,
								older,
								P7_SKIP,
							)
							if err == nil {
								_P7SameChoice(
									t,
									skipped,
									want,
								)
							}

							return err
						},
					)
				},
			)
		}
	}

	if unknown == 0 {
		t.Fatalf("no row of ChExt2 is unknown to ChExt1")
	}
}

// TestChoice_NewerDecoder decodes the encodings of ChExt1 with the codec of
// ChExt2: the alternatives of the older type keep their indices (X.691 23.2).
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestChoice_NewerDecoder(t *testing.T) {
	var (
		file  = _P7Load(t)
		older = P7_CHOICES["ChExt1"]
		newer = P7_CHOICES["ChExt2"]
	)

	for _, aligned := range []bool{true, false} {
		for index, row := range _P7Of(
			file.Choice,
			"ChExt1",
		) {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+_P7Name(
					row,
					index,
				),
				func(t *testing.T) {
					got, err := _P7DecodeChoice(
						DECODERS[aligned](_Unhex(
							t,
							_P7Want(
								row,
								aligned,
							).hex,
						)),
						newer,
						P7_KEEP,
					)
					if err != nil {
						t.Fatalf(
							"decode = %v",
							err,
						)
					}

					_P7SameChoice(
						t,
						got,
						_P7ParseChoice(
							t,
							older,
							row.Value,
						),
					)
				},
			)
		}
	}
}
