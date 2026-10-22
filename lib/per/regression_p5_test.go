package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// ALLOC_RUNS is the number of runs of one AllocsPerRun measurement, and
// ALLOC_DECODE_MAX the allocations a decode may make: the result string.
const (
	ALLOC_RUNS       = 200
	ALLOC_DECODE_MAX = 1
	HUGE_SIZE        = int64(1) << 62
	BIG_SIZE         = int64(1) << 40
)

// _P5AllocCase is one decode whose allocations are counted.
type _P5AllocCase struct {
	name   string
	kind   per.StringKind
	value  string
	size   *per.Constraint
	chars  string
	hasSet bool
}

// TestRegression_P5DecodeAllocations checks the plan rule "codecs make no
// allocation for each value" (.agents/builtin-support.md, Phases 3 to 8) for the
// decoders of the restricted character strings: review P5-10. A decode may
// allocate the result string and nothing else, net of the decoder's own
// construction, which is measured and subtracted.
//
// Revisions:
//   - 2026-10-19 13:15: initial creation
func TestRegression_P5DecodeAllocations(t *testing.T) {
	cases := []*_P5AllocCase{
		{
			name:  "ia5",
			kind:  per.STRING_IA5,
			value: "hello world",
			size:  per.Unconstrained(),
		},
		{
			name:  "ia5_size",
			kind:  per.STRING_IA5,
			value: "hello",
			size: per.Constrained(
				1,
				8,
			),
		},
		{
			name:  "numeric",
			kind:  per.STRING_NUMERIC,
			value: "0123456789",
			size:  per.Unconstrained(),
		},
		{
			name:  "bmp",
			kind:  per.STRING_BMP,
			value: "héllo中",
			size:  per.Unconstrained(),
		},
		{
			name:  "universal",
			kind:  per.STRING_UNIVERSAL,
			value: "h\U0001F600llo",
			size:  per.Unconstrained(),
		},
		{
			name:  "utf8",
			kind:  per.STRING_UTF8,
			value: "héllo",
			size:  per.Unconstrained(),
		},
		{
			name:  "general",
			kind:  per.STRING_GENERAL,
			value: "hello world",
			size:  per.Unconstrained(),
		},
		{
			name:  "from_acgt",
			kind:  per.STRING_IA5,
			value: "GATTACA",
			size: per.Constrained(
				1,
				9,
			),
			chars:  "ACGT",
			hasSet: true,
		},
	}

	for _, tc := range cases {
		for _, aligned := range []bool{true, false} {
			t.Run(
				tc.name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					_P5CheckDecodeAllocs(
						t,
						aligned,
						tc,
					)
				},
			)
		}
	}
}

// _P5CheckDecodeAllocs counts the allocations of one decode.
//
// Revisions:
//   - 2026-10-19 13:15: initial creation
func _P5CheckDecodeAllocs(
	t *testing.T,
	aligned bool,
	tc *_P5AllocCase,
) {
	t.Helper()

	var alphabet *per.Alphabet

	enc := ENCODERS[aligned]()

	if tc.hasSet {
		var err error

		alphabet, err = per.NewAlphabet(
			tc.kind,
			tc.chars,
		)
		if err != nil {
			t.Fatalf(
				"NewAlphabet = %v",
				err,
			)
		}

		if err := enc.EncodeAlphabetString(
			tc.value,
			alphabet,
			tc.size,
		); err != nil {
			t.Fatalf(
				"encode = %v",
				err,
			)
		}
	} else if err := enc.EncodeRestrictedString(
		tc.value,
		tc.kind,
		tc.size,
	); err != nil {
		t.Fatalf(
			"encode = %v",
			err,
		)
	}

	var (
		data = enc.Bytes()

		base = testing.AllocsPerRun(
			ALLOC_RUNS,
			func() {
				_ = DECODERS[aligned](data)
			},
		)
		total = testing.AllocsPerRun(
			ALLOC_RUNS,
			func() {
				dec := DECODERS[aligned](data)

				if tc.hasSet {
					_, _ = dec.DecodeAlphabetString(
						alphabet,
						tc.size,
					)

					return
				}

				_, _ = dec.DecodeRestrictedString(
					tc.kind,
					tc.size,
				)
			},
		)
	)

	if got := total - base; got > ALLOC_DECODE_MAX {
		t.Errorf(
			"decode makes %.0f allocations, want at most %d",
			got,
			ALLOC_DECODE_MAX,
		)
	}
}

// TestRegression_P5AlignOverflow checks the alignment decision of X.691 clause 30.5.7
// for a size whose upper bound times the bits per character overflows uint64:
// review P5-11. UniversalString has 32 bits per character, so SIZE(0..2^62) has
// aub*b = 2^67, which wraps to 0 in uint64. The decision is aub*b >= 16, so the
// field is octet-aligned in APER. For a bound of 64K or more the length is the
// unconstrained form (11.9.3.5, 11.9.3.6: one octet below 128, octet-aligned), so
// the length is the same for SIZE(0..2^62) and SIZE(0..2^40). Both oracles accept
// both bounds and agree on 02 00000061 00000062 for "ab" (checked by hand, once, in a module
// that is retired). A BOOLEAN comes first, so that the value is not at an octet
// boundary when the length is written.
//
// Revisions:
//   - 2026-10-19 13:15: initial creation
func TestRegression_P5AlignOverflow(t *testing.T) {
	var (
		want = map[bool][]byte{
			true:  {0x80, 0x02, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x62},
			false: nil,
		}
		sizes = map[string]int64{
			"two_pow_62": HUGE_SIZE,
			"two_pow_40": BIG_SIZE,
		}
	)

	for name, upper := range sizes {
		for _, aligned := range []bool{true, false} {
			t.Run(
				name+"/"+VARIANT_NAMES[aligned],
				func(t *testing.T) {
					_P5CheckOverflow(
						t,
						aligned,
						per.Constrained(
							0,
							upper,
						),
						want[aligned],
					)
				},
			)
		}
	}
}

// _P5CheckOverflow encodes a BOOLEAN and "ab", compares with want in APER, and decodes.
// UPER has no padding, so it is checked by the round trip only.
//
// Revisions:
//   - 2026-10-19 13:15: initial creation
func _P5CheckOverflow(
	t *testing.T,
	aligned bool,
	size *per.Constraint,
	want []byte,
) {
	t.Helper()

	enc := ENCODERS[aligned]()
	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatalf(
			"EncodeBoolean = %v",
			err,
		)
	}

	if err := enc.EncodeRestrictedString(
		"ab",
		per.STRING_UNIVERSAL,
		size,
	); err != nil {
		t.Fatalf(
			"encode = %v",
			err,
		)
	}

	if want != nil {
		_Compare(
			t,
			enc.Bytes(),
			want,
		)
	}

	var (
		dec = DECODERS[aligned](enc.Bytes())

		flag, err = dec.DecodeBoolean()
	)
	if err != nil || !flag {
		t.Fatalf(
			"DecodeBoolean = %v, %v",
			flag,
			err,
		)
	}

	got, err := dec.DecodeRestrictedString(
		per.STRING_UNIVERSAL,
		size,
	)
	if err != nil || got != "ab" {
		t.Fatalf(
			"decode = %q, %v",
			got,
			err,
		)
	}
}
