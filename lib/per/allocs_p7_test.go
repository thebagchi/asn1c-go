package per_test

import (
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// ALLOC_OPEN_TYPE_MAX is what DecodeOpenType may allocate: the copy of the inner
// octets. In UNALIGNED the inner octets start at any bit of the input (the length
// of 11.9.3.6 is not aligned there), so no view of the input can hold them, and
// the decoder returns a copy. In ALIGNED a view would do, but one rule keeps the
// result valid after the input is gone.
const (
	ALLOC_OPEN_TYPE_MAX = 1
)

// ErrCountStateP7 reports a Count that does not say More after the first part of
// a list of 40000 components.
var (
	ErrCountStateP7 = errors.New("count does not report a second part")
)

// _P7AllocCase is one primitive of this phase. write runs on an encoder after a
// BOOLEAN; read runs on a decoder after the BOOLEAN, over the octets that write
// made. A nil read or write leaves that side out.
type _P7AllocCase struct {
	name  string
	max   float64
	write func(enc *per.Encoder) error
	read  func(dec *per.Decoder) error
}

// _P7AllocCases builds the cases. The bits belong to the cases, as they belong to
// the caller in generated code, so that no run allocates them.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7AllocCases() []*_P7AllocCase {
	var (
		preamble  = _P7Bits(4)
		readBack  = _P7Bits(4)
		additions = _P7Bits(3)
		readAdd   = _P7Bits(3)
		inner     = _FragmentOctets(5)
	)

	_P7Mark(
		preamble,
		0,
	)
	_P7Mark(
		preamble,
		2,
	)
	_P7Mark(
		additions,
		1,
	)

	return []*_P7AllocCase{
		{
			name: "Preamble",
			write: func(enc *per.Encoder) error {
				return enc.EncodePreamble(preamble)
			},
			read: func(dec *per.Decoder) error {
				return dec.DecodePreamble(readBack)
			},
		},
		{
			name: "Additions",
			write: func(enc *per.Encoder) error {
				return enc.EncodeAdditions(additions)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeAdditions(readAdd)

				return err
			},
		},
		{
			name: "CountBounded",
			write: func(enc *per.Encoder) error {
				var count per.Count

				return enc.EncodeCount(
					&count,
					5,
					P7_LISTS["Seq10"].size,
				)
			},
			read: func(dec *per.Decoder) error {
				var count per.Count

				return dec.DecodeCount(
					&count,
					P7_LISTS["Seq10"].size,
				)
			},
		},
		{
			name: "CountExtensible",
			write: func(enc *per.Encoder) error {
				var count per.Count

				return enc.EncodeCount(
					&count,
					11,
					P7_LISTS["SeqExt"].size,
				)
			},
			read: func(dec *per.Decoder) error {
				var count per.Count

				return dec.DecodeCount(
					&count,
					P7_LISTS["SeqExt"].size,
				)
			},
		},
		{
			name:  "CountAndNext",
			write: _P7WriteParts,
			read:  _P7ReadParts,
		},
		{
			name: "OpenType",
			max:  ALLOC_OPEN_TYPE_MAX,
			write: func(enc *per.Encoder) error {
				return enc.EncodeOpenType(inner)
			},
			read: func(dec *per.Decoder) error {
				_, err := dec.DecodeOpenType()

				return err
			},
		},
		{
			name: "SkipOpenTypes",
			write: func(enc *per.Encoder) error {
				if err := enc.EncodeOpenType(inner); err != nil {
					return err
				}

				return enc.EncodeOpenType(inner)
			},
			read: func(dec *per.Decoder) error {
				return dec.SkipOpenTypes(2)
			},
		},
	}
}

// _P7WriteParts writes the lengths of a list of 40000 components, 32K and then
// 7232, one after the other with no component between them: the allocations of
// the two primitives are what is measured. An encoder cannot tell that the
// components are missing.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7WriteParts(enc *per.Encoder) error {
	var count per.Count

	if err := enc.EncodeCount(
		&count,
		40000,
		per.Unconstrained(),
	); err != nil {
		return err
	}

	if !count.More() {
		return ErrCountStateP7
	}

	return enc.EncodeNext(&count)
}

// _P7ReadParts reads the two lengths that _P7WriteParts wrote.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7ReadParts(dec *per.Decoder) error {
	var count per.Count

	if err := dec.DecodeCount(
		&count,
		per.Unconstrained(),
	); err != nil {
		return err
	}

	if !count.More() {
		return ErrCountStateP7
	}

	return dec.DecodeNext(&count)
}

// TestAllocs_Primitives checks the plan rule that a codec makes no allocation for
// each value (.agents/builtin-support.md, Phases 3 to 8): EncodePreamble,
// DecodePreamble, EncodeAdditions, DecodeAdditions, EncodeCount, EncodeNext,
// DecodeCount, DecodeNext, EncodeOpenType and SkipOpenTypes make none, and
// DecodeOpenType makes at most the copy of the inner octets. The count is the
// allocations of a run that makes the encoder or decoder, writes or reads a
// BOOLEAN and then calls the primitive, less those of the same run without the
// call, in both variants. A primitive that fails makes the test fail, so a stub
// does not pass by returning early.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func TestAllocs_Primitives(t *testing.T) {
	for _, aligned := range []bool{true, false} {
		for _, tc := range _P7AllocCases() {
			t.Run(
				VARIANT_NAMES[aligned]+"_"+tc.name,
				func(t *testing.T) {
					data := _P7AllocEncode(
						t,
						aligned,
						tc,
					)

					_P7AllocDecode(
						t,
						aligned,
						tc,
						data,
					)
				},
			)
		}
	}
}

// _P7AllocEncode measures the encoder side of a case, and returns the octets that
// the decoder side reads.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7AllocEncode(
	t *testing.T,
	aligned bool,
	tc *_P7AllocCase,
) []byte {
	t.Helper()

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

	if got := total - base; got > tc.max {
		t.Errorf(
			"encode makes %.0f allocations, want at most %.0f",
			got,
			tc.max,
		)
	}

	return enc.Bytes()
}

// _P7AllocDecode measures the decoder side of a case over data.
//
// Revisions:
//   - 2026-10-19 14:18: initial creation
func _P7AllocDecode(
	t *testing.T,
	aligned bool,
	tc *_P7AllocCase,
	data []byte,
) {
	t.Helper()

	dec := DECODERS[aligned](data)

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

	if got := total - base; got > tc.max {
		t.Errorf(
			"decode makes %.0f allocations, want at most %.0f",
			got,
			tc.max,
		)
	}
}
