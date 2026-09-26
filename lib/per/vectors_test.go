package per_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// The vectors under testing/ were produced by Erlang's asn1ct, so a mismatch
// here is a disagreement with a second implementation rather than with an
// earlier version of this one.
const (
	VECTOR_BOOL    = "bool.json"
	VECTOR_INTEGER = "integer.json"
	VECTOR_OCTETS  = "octet_string.json"
	VECTOR_BITS    = "bit_string.json"
	VECTOR_ENUM    = "enumerated.json"
	VECTOR_REAL    = "real.json"
)

// Constructors keyed by the variant, so no helper below takes a bare boolean
// and decides what to build from it.
var (
	encoders = map[bool]func() *per.Encoder{
		true:  per.NewAlignedEncoder,
		false: per.NewUnalignedEncoder,
	}
	decoders = map[bool]func([]byte) *per.Decoder{
		true:  per.NewAlignedDecoder,
		false: per.NewUnalignedDecoder,
	}
)

type sizeInput struct {
	Lb     *int64 `json:"lb"`
	Ub     *int64 `json:"ub"`
	Ext    *bool  `json:"extensible"`
	Length uint64 `json:"length"`
}

type intInput struct {
	Lb    *int64 `json:"lb"`
	Ub    *int64 `json:"ub"`
	Ext   *bool  `json:"extensible"`
	Value int64  `json:"value"`
}

type enumInput struct {
	Value uint64 `json:"value"`
	Count uint64 `json:"count"`
	Ext   bool   `json:"extensible"`
}

type boolVector struct {
	Output  string `json:"output"`
	Input   bool   `json:"input"`
	Aligned bool   `json:"aligned"`
}

type intVector struct {
	Input   intInput `json:"input"`
	Output  string   `json:"output"`
	Aligned bool     `json:"aligned"`
}

type sizeVector struct {
	Input   sizeInput `json:"input"`
	Output  string    `json:"output"`
	Aligned bool      `json:"aligned"`
}

type enumVector struct {
	Input   enumInput `json:"input"`
	Output  string    `json:"output"`
	Aligned bool      `json:"aligned"`
}

type realVector struct {
	Input struct {
		Value json.RawMessage `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// TestVectorBoolean checks BOOLEAN against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestVectorBoolean(t *testing.T) {
	var vectors []boolVector

	load(t, VECTOR_BOOL, &vectors)

	for _, tc := range vectors {
		label := fmt.Sprintf("value_%v_aligned_%v", tc.Input, tc.Aligned)

		t.Run(label, func(t *testing.T) {
			encoder := encoders[tc.Aligned]()
			if err := encoder.EncodeBoolean(tc.Input); err != nil {
				t.Fatalf("EncodeBoolean: %v", err)
			}

			want := unhex(t, tc.Output)
			compare(t, encoder.Bytes(), want)

			got, err := decoders[tc.Aligned](want).DecodeBoolean()
			if err != nil {
				t.Fatalf("DecodeBoolean: %v", err)
			}

			if got != tc.Input {
				t.Errorf("DecodeBoolean() = %v, want %v", got, tc.Input)
			}
		})
	}
}

// TestVectorInteger checks INTEGER against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestVectorInteger(t *testing.T) {
	var vectors []intVector

	load(t, VECTOR_INTEGER, &vectors)

	for _, tc := range vectors {
		label := fmt.Sprintf(
			"value_%d_lb_%s_ub_%s_aligned_%v_ext_%s",
			tc.Input.Value, show(tc.Input.Lb), show(tc.Input.Ub),
			tc.Aligned, show(tc.Input.Ext),
		)

		t.Run(label, func(t *testing.T) {
			size := constraint(tc.Input.Lb, tc.Input.Ub, tc.Input.Ext)

			encoder := encoders[tc.Aligned]()
			if err := encoder.EncodeInteger(tc.Input.Value, size); err != nil {
				t.Fatalf("EncodeInteger: %v", err)
			}

			want := unhex(t, tc.Output)
			compare(t, encoder.Bytes(), want)

			got, err := decoders[tc.Aligned](want).DecodeInteger(size)
			if err != nil {
				t.Fatalf("DecodeInteger: %v", err)
			}

			if got != tc.Input.Value {
				t.Errorf("DecodeInteger() = %d, want %d", got, tc.Input.Value)
			}
		})
	}
}

// TestVectorOctetString checks OCTET STRING against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestVectorOctetString(t *testing.T) {
	var vectors []sizeVector

	load(t, VECTOR_OCTETS, &vectors)

	for _, tc := range vectors {
		t.Run(sizeName("octets", &tc.Input, tc.Aligned), func(t *testing.T) {
			var (
				size  = constraint(tc.Input.Lb, tc.Input.Ub, tc.Input.Ext)
				value = octets(tc.Input.Length)
			)

			encoder := encoders[tc.Aligned]()
			if err := encoder.EncodeOctetString(value, size); err != nil {
				t.Fatalf("EncodeOctetString: %v", err)
			}

			want := unhex(t, tc.Output)
			compare(t, encoder.Bytes(), want)

			got, err := decoders[tc.Aligned](want).DecodeOctetString(size)
			if err != nil {
				t.Fatalf("DecodeOctetString: %v", err)
			}

			if !bytes.Equal(got, value) {
				t.Errorf("DecodeOctetString() = % x, want % x", got, value)
			}
		})
	}
}

// TestVectorBitString checks BIT STRING against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestVectorBitString(t *testing.T) {
	var vectors []sizeVector

	load(t, VECTOR_BITS, &vectors)

	for _, tc := range vectors {
		t.Run(sizeName("bits", &tc.Input, tc.Aligned), func(t *testing.T) {
			var (
				size  = constraint(tc.Input.Lb, tc.Input.Ub, tc.Input.Ext)
				value = bitstring(tc.Input.Length)
			)

			encoder := encoders[tc.Aligned]()
			if err := encoder.EncodeBitString(value, size); err != nil {
				t.Fatalf("EncodeBitString: %v", err)
			}

			want := unhex(t, tc.Output)
			compare(t, encoder.Bytes(), want)

			got, err := decoders[tc.Aligned](want).DecodeBitString(size)
			if err != nil {
				t.Fatalf("DecodeBitString: %v", err)
			}

			if got.BitLength != value.BitLength {
				t.Fatalf("BitLength = %d, want %d", got.BitLength, value.BitLength)
			}

			if !bytes.Equal(got.Bytes, value.Bytes) {
				t.Errorf("Bytes = % x, want % x", got.Bytes, value.Bytes)
			}
		})
	}
}

// TestVectorEnumerated checks ENUMERATED against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestVectorEnumerated(t *testing.T) {
	var vectors []enumVector

	load(t, VECTOR_ENUM, &vectors)

	for _, tc := range vectors {
		label := fmt.Sprintf(
			"value_%d_count_%d_aligned_%v_ext_%v",
			tc.Input.Value, tc.Input.Count, tc.Aligned, tc.Input.Ext,
		)

		t.Run(label, func(t *testing.T) {
			root := per.Constrained(0, int64(tc.Input.Count)-1)
			if tc.Input.Ext {
				root = root.Extensible()
			}

			encoder := encoders[tc.Aligned]()
			if err := encoder.EncodeEnumerated(tc.Input.Value, root); err != nil {
				t.Fatalf("EncodeEnumerated: %v", err)
			}

			want := unhex(t, tc.Output)
			compare(t, encoder.Bytes(), want)

			got, err := decoders[tc.Aligned](want).DecodeEnumerated(root)
			if err != nil {
				t.Fatalf("DecodeEnumerated: %v", err)
			}

			if got != tc.Input.Value {
				t.Errorf("DecodeEnumerated() = %d, want %d", got, tc.Input.Value)
			}
		})
	}
}

// TestVectorReal checks REAL against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestVectorReal(t *testing.T) {
	var vectors []realVector

	load(t, VECTOR_REAL, &vectors)

	for _, tc := range vectors {
		value := asReal(t, tc.Input.Value)

		t.Run(fmt.Sprintf("value_%g_aligned_%v", value, tc.Aligned), func(t *testing.T) {
			encoder := encoders[tc.Aligned]()
			if err := encoder.EncodeReal(value); err != nil {
				t.Fatalf("EncodeReal: %v", err)
			}

			want := unhex(t, tc.Output)
			compare(t, encoder.Bytes(), want)

			got, err := decoders[tc.Aligned](want).DecodeReal()
			if err != nil {
				t.Fatalf("DecodeReal: %v", err)
			}

			if !sameReal(got, value) {
				t.Errorf("DecodeReal() = %v, want %v", got, value)
			}
		})
	}
}

// load reads a vector file into out.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func load(t *testing.T, name string, out any) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testing", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

// unhex turns a vector's expected output into the bytes it names.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func unhex(t *testing.T, text string) []byte {
	t.Helper()

	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("decode %q: %v", text, err)
	}

	return data
}

// compare reports an encoding that differs from the vector's.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func compare(t *testing.T, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Fatalf("encoded % x, want % x", got, want)
	}
}

// constraint builds the constraint a vector describes.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func constraint(lb, ub *int64, ext *bool) *per.Constraint {
	var size *per.Constraint

	switch {
	case lb != nil && ub != nil:
		size = per.Constrained(*lb, *ub)
	case lb != nil:
		size = per.SemiConstrained(*lb)
	case ub != nil:
		size = per.Bounded(*ub)
	default:
		size = per.Unconstrained()
	}

	if ext != nil && *ext {
		size = size.Extensible()
	}

	return size
}

// show renders an optional bound for a subtest name.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func show[T any](value *T) string {
	if value == nil {
		return "nil"
	}

	return fmt.Sprintf("%v", *value)
}

// sizeName builds the subtest name of a length-constrained vector.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func sizeName(kind string, in *sizeInput, aligned bool) string {
	return fmt.Sprintf(
		"%s_len_%d_lb_%s_ub_%s_aligned_%v_ext_%s",
		kind, in.Length, show(in.Lb), show(in.Ub), aligned, show(in.Ext),
	)
}

// octets builds the octet string of the given length that the vectors describe.
//
// Revisions:
//   - 2026-02-06 16:21: initial creation as GenOctetString
func octets(length uint64) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i % 256)
	}

	return data
}

// bitstring builds the alternating bit string of the given length that the
// vectors describe.
//
// Revisions:
//   - 2026-02-06 16:21: initial creation as GenBitString
func bitstring(length uint64) *asn1.BitString {
	data := make([]byte, (length+7)/8)
	for i := range length {
		// The vectors alternate 0, 1, 0, 1 from the leading bit.
		if i%2 == 1 {
			data[i/8] |= 1 << (7 - i%8)
		}
	}

	return &asn1.BitString{
		Bytes:     data,
		BitLength: int(length),
	}
}

// asReal parses a vector's value, which is a number or the name of one of the
// values IEEE 754 has no literal for.
//
// Revisions:
//   - 2026-02-06 16:21: initial creation as parseRealValue
func asReal(t *testing.T, raw json.RawMessage) float64 {
	t.Helper()

	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		switch name {
		case "Inf":
			return math.Inf(1)
		case "-Inf":
			return math.Inf(-1)
		case "NaN":
			return math.NaN()
		case "-0":
			return math.Copysign(0, -1)
		default:
			t.Fatalf("unknown special real %q", name)
		}
	}

	var value float64
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("parse real %s: %v", raw, err)
	}

	return value
}

// sameReal compares two reals, counting two NaNs as equal and distinguishing
// the two zeroes, neither of which == does.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func sameReal(got, want float64) bool {
	if math.IsNaN(want) {
		return math.IsNaN(got)
	}

	if want == 0 {
		return got == 0 && math.Signbit(got) == math.Signbit(want)
	}

	return got == want
}
