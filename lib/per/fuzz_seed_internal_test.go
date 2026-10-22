package per

import (
	"testing"
)

// This file is an internal test because the fuzz seeds are written with the encoders of the
// package, and the decoders under fuzz read the bit counts of the same codec. A function that
// round trips takes its seeds from _FuzzSeedValue (fuzz_internal_test.go). The helpers here
// serve the three functions that only check for a panic.

// _FuzzSeeds writes one value with the aligned encoder and with the unaligned encoder, and
// returns the two octet strings, each behind the variant octet of its encoder. The harness
// reads that octet, so each seed is decoded in the variant that wrote it.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 18:56: puts the variant octet in front of each seed
func _FuzzSeeds(
	f *testing.F,
	write func(enc *Encoder) error,
) [][]byte {
	f.Helper()

	var (
		encoders = map[byte]*Encoder{
			FUZZ_ALIGNED:   NewAlignedEncoder(),
			FUZZ_UNALIGNED: NewUnalignedEncoder(),
		}
		seeds = make(
			[][]byte,
			0,
			len(encoders),
		)
	)

	for variant, enc := range encoders {
		if err := write(enc); err != nil {
			f.Fatalf(
				"seed does not encode: %v",
				err,
			)
		}

		seeds = append(
			seeds,
			append(
				[]byte{
					variant,
				},
				enc.Bytes()...,
			),
		)
	}

	return seeds
}

// _FuzzSeedPick adds the octets of one value, in both variants, as seeds with the selector
// octet in front, the octet that _Pick reads. Only the functions that check for a panic call
// it; a round trip uses _FuzzSeedValue, which also checks that the seed decodes.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
func _FuzzSeedPick(
	f *testing.F,
	pick byte,
	write func(enc *Encoder) error,
) {
	f.Helper()

	for _, seed := range _FuzzSeeds(
		f,
		write,
	) {
		f.Add(
			append(
				[]byte{pick},
				seed...,
			),
		)
	}
}

// _FuzzDecodeOnly runs a decoder on data in the variant its first octet picks, as
// _FuzzRoundTrip does. A decoder that keeps no value for an encoder to write back has
// nothing to round trip, so the check is that it does not panic.
//
// Revisions:
//   - 2026-10-21 18:50: initial creation (review P29-3)
//   - 2026-10-21 18:56: the first octet picks the variant
func _FuzzDecodeOnly(
	t *testing.T,
	data []byte,
	decode func(dec *Decoder) error,
) {
	t.Helper()

	if len(data) == 0 {
		return
	}

	dec := NewUnalignedDecoder(data[1:])
	if data[0]&FUZZ_ALIGNED != 0 {
		dec = NewAlignedDecoder(data[1:])
	}

	if err := decode(dec); err != nil {
		t.Logf(
			"aligned %t: %x does not decode: %v",
			dec.aligned,
			data,
			err,
		)
	}
}
