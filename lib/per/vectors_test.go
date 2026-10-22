package per_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// The vectors under testing/ were produced by two oracles, pycrate and Erlang's asn1ct, from
// the one file testing/testing.asn1, and testing/testing.py wrote them all into
// testing/testing.json. A mismatch here is a disagreement with them rather than with an
// earlier version of this code. Each VECTOR_ constant is the key of one kind of vectors in
// that file.
const (
	TESTING_FILE   = "testing.json"
	VECTOR_BOOL    = "bool"
	VECTOR_INTEGER = "integer"
	VECTOR_OCTETS  = "octet_string"
	VECTOR_BITS    = "bit_string"
	VECTOR_ENUM    = "enumerated"
	VECTOR_REAL    = "real"
)

// Constructors keyed by the variant, so no helper below takes a bare boolean
// and decides what to build from it.
var (
	ENCODERS = map[bool]func() *per.Encoder{
		true:  per.NewAlignedEncoder,
		false: per.NewUnalignedEncoder,
	}
	DECODERS = map[bool]func([]byte) *per.Decoder{
		true:  per.NewAlignedDecoder,
		false: per.NewUnalignedDecoder,
	}
)

// The kinds of vectors in testing/testing.json, read once. A kind is kept as the raw text
// that _Load decodes into the type a test wants.
var (
	TESTING_ONCE  sync.Once
	TESTING_KINDS map[string]json.RawMessage
	TESTING_ERR   error
)

// _Expected holds the octets that a vector expects in each variant. A short answer is hex
// text. A long answer is its sha256 and its length in octets.
type _Expected struct {
	Aper       string `json:"aper"`
	Uper       string `json:"uper"`
	AperSha256 string `json:"aper_sha256"`
	UperSha256 string `json:"uper_sha256"`
	AperOctets int    `json:"aper_octets"`
	UperOctets int    `json:"uper_octets"`
}

type _SizeInput struct {
	Lb     *int64 `json:"lb"`
	Ub     *int64 `json:"ub"`
	Ext    *bool  `json:"extensible"`
	Length uint64 `json:"length"`
}

type _IntInput struct {
	Lb    *int64 `json:"lb"`
	Ub    *int64 `json:"ub"`
	Ext   *bool  `json:"extensible"`
	Value int64  `json:"value"`
}

type _EnumInput struct {
	Value uint64 `json:"value"`
	Count uint64 `json:"count"`
	Ext   bool   `json:"extensible"`
}

type _BoolVector struct {
	_Expected
	Input bool `json:"input"`
}

type _IntVector struct {
	_Expected
	Input *_IntInput `json:"input"`
}

type _SizeVector struct {
	_Expected
	Input *_SizeInput `json:"input"`
}

type _EnumVector struct {
	_Expected
	Input *_EnumInput `json:"input"`
}

type _RealVector struct {
	_Expected
	Input struct {
		Value json.RawMessage `json:"value"`
	} `json:"input"`
}

// TestVectorBoolean checks BOOLEAN against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:20: read the rows of testing.json, which has one row for both variants; check
//     a long
//     answer by its sha256 and length
func TestVectorBoolean(t *testing.T) {
	var vectors []_BoolVector

	_Load(
		t,
		VECTOR_BOOL,
		&vectors,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range vectors {
			label := fmt.Sprintf(
				"value_%v_aligned_%v",
				tc.Input,
				aligned,
			)

			t.Run(
				label,
				func(t *testing.T) {
					encoder := ENCODERS[aligned]()
					if err := encoder.EncodeBoolean(tc.Input); err != nil {
						t.Fatalf(
							"EncodeBoolean: %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							encoder.Bytes(),
						)

						got, err = DECODERS[aligned](want).DecodeBoolean()
					)
					if err != nil {
						t.Fatalf(
							"DecodeBoolean: %v",
							err,
						)
					}

					if got != tc.Input {
						t.Errorf(
							"DecodeBoolean() = %v, want %v",
							got,
							tc.Input,
						)
					}
				},
			)
		}
	}
}

// TestVectorInteger checks INTEGER against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:20: read the rows of testing.json, which has one row for both variants; check
//     a long
//     answer by its sha256 and length
func TestVectorInteger(t *testing.T) {
	var vectors []_IntVector

	_Load(
		t,
		VECTOR_INTEGER,
		&vectors,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range vectors {
			label := fmt.Sprintf(
				"value_%d_lb_%s_ub_%s_aligned_%v_ext_%s",
				tc.Input.Value,
				_Show(tc.Input.Lb),
				_Show(tc.Input.Ub),
				aligned,
				_Show(tc.Input.Ext),
			)

			t.Run(
				label,
				func(t *testing.T) {
					var (
						size = _Constraint(
							tc.Input.Lb,
							tc.Input.Ub,
							tc.Input.Ext,
						)

						encoder = ENCODERS[aligned]()
					)
					if err := encoder.EncodeInteger(
						tc.Input.Value,
						size,
					); err != nil {
						t.Fatalf(
							"EncodeInteger: %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							encoder.Bytes(),
						)

						got, err = DECODERS[aligned](want).DecodeInteger(
							size,
						)
					)
					if err != nil {
						t.Fatalf(
							"DecodeInteger: %v",
							err,
						)
					}

					if got != tc.Input.Value {
						t.Errorf(
							"DecodeInteger() = %d, want %d",
							got,
							tc.Input.Value,
						)
					}
				},
			)
		}
	}
}

// TestVectorOctetString checks OCTET STRING against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:20: read the rows of testing.json, which has one row for both variants; check
//     a long
//     answer by its sha256 and length
func TestVectorOctetString(t *testing.T) {
	var vectors []_SizeVector

	_Load(
		t,
		VECTOR_OCTETS,
		&vectors,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range vectors {
			t.Run(
				_SizeName(
					"octets",
					tc.Input,
					aligned,
				),
				func(t *testing.T) {
					var (
						size = _Constraint(
							tc.Input.Lb,
							tc.Input.Ub,
							tc.Input.Ext,
						)
						value = _Octets(tc.Input.Length)
					)

					encoder := ENCODERS[aligned]()
					if err := encoder.EncodeOctetString(
						value,
						size,
					); err != nil {
						t.Fatalf(
							"EncodeOctetString: %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							encoder.Bytes(),
						)

						got, err = DECODERS[aligned](
							want,
						).DecodeOctetString(
							size,
						)
					)
					if err != nil {
						t.Fatalf(
							"DecodeOctetString: %v",
							err,
						)
					}

					if !bytes.Equal(
						got,
						value,
					) {
						t.Errorf(
							"DecodeOctetString() = % x, want % x",
							got,
							value,
						)
					}
				},
			)
		}
	}
}

// TestVectorBitString checks BIT STRING against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:20: read the rows of testing.json, which has one row for both variants; check
//     a long
//     answer by its sha256 and length
func TestVectorBitString(t *testing.T) {
	var vectors []_SizeVector

	_Load(
		t,
		VECTOR_BITS,
		&vectors,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range vectors {
			t.Run(
				_SizeName(
					"bits",
					tc.Input,
					aligned,
				),
				func(t *testing.T) {
					var (
						size = _Constraint(
							tc.Input.Lb,
							tc.Input.Ub,
							tc.Input.Ext,
						)
						value = _Bitstring(tc.Input.Length)
					)

					encoder := ENCODERS[aligned]()
					if err := encoder.EncodeBitString(
						value,
						size,
					); err != nil {
						t.Fatalf(
							"EncodeBitString: %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							encoder.Bytes(),
						)

						got, err = DECODERS[aligned](want).DecodeBitString(
							size,
						)
					)
					if err != nil {
						t.Fatalf(
							"DecodeBitString: %v",
							err,
						)
					}

					if got.BitLength != value.BitLength {
						t.Fatalf(
							"BitLength = %d, want %d",
							got.BitLength,
							value.BitLength,
						)
					}

					if !bytes.Equal(
						got.Bytes,
						value.Bytes,
					) {
						t.Errorf(
							"Bytes = % x, want % x",
							got.Bytes,
							value.Bytes,
						)
					}
				},
			)
		}
	}
}

// TestVectorEnumerated checks ENUMERATED against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:20: read the rows of testing.json, which has one row for both variants; check
//     a long
//     answer by its sha256 and length
func TestVectorEnumerated(t *testing.T) {
	var vectors []_EnumVector

	_Load(
		t,
		VECTOR_ENUM,
		&vectors,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range vectors {
			label := fmt.Sprintf(
				"value_%d_count_%d_aligned_%v_ext_%v",
				tc.Input.Value,
				tc.Input.Count,
				aligned,
				tc.Input.Ext,
			)

			t.Run(
				label,
				func(t *testing.T) {
					root := per.Constrained(
						0,
						int64(tc.Input.Count)-1,
					)
					if tc.Input.Ext {
						root = root.Extensible()
					}

					encoder := ENCODERS[aligned]()
					if err := encoder.EncodeEnumerated(
						tc.Input.Value,
						root,
					); err != nil {
						t.Fatalf(
							"EncodeEnumerated: %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							encoder.Bytes(),
						)

						got, err = DECODERS[aligned](
							want,
						).DecodeEnumerated(
							root,
						)
					)
					if err != nil {
						t.Fatalf(
							"DecodeEnumerated: %v",
							err,
						)
					}

					if got != tc.Input.Value {
						t.Errorf(
							"DecodeEnumerated() = %d, want %d",
							got,
							tc.Input.Value,
						)
					}
				},
			)
		}
	}
}

// TestVectorReal checks REAL against its vectors, both ways.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:20: read the rows of testing.json, which has one row for both variants; check
//     a long
//     answer by its sha256 and length
func TestVectorReal(t *testing.T) {
	var vectors []_RealVector

	_Load(
		t,
		VECTOR_REAL,
		&vectors,
	)

	for _, aligned := range []bool{true, false} {
		for _, tc := range vectors {
			value := _AsReal(
				t,
				tc.Input.Value,
			)

			t.Run(
				fmt.Sprintf(
					"value_%g_aligned_%v",
					value,
					aligned,
				),
				func(t *testing.T) {
					encoder := ENCODERS[aligned]()
					if err := encoder.EncodeReal(value); err != nil {
						t.Fatalf(
							"EncodeReal: %v",
							err,
						)
					}

					var (
						want = tc._Check(
							t,
							aligned,
							encoder.Bytes(),
						)

						got, err = DECODERS[aligned](want).DecodeReal()
					)
					if err != nil {
						t.Fatalf(
							"DecodeReal: %v",
							err,
						)
					}

					if !_SameReal(
						got,
						value,
					) {
						t.Errorf(
							"DecodeReal() = %v, want %v",
							got,
							value,
						)
					}
				},
			)
		}
	}
}

// _Load reads the vectors of one kind from testing/testing.json into out. The file is read
// once for the whole run. A row there holds the answers of both oracles; _Load gives the
// decoder the expected answer of each variant (see _Flatten).
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-10-20 00:21: read one kind of the one file testing.json, not a file of its own
func _Load(
	t *testing.T,
	name string,
	out any,
) {
	t.Helper()

	TESTING_ONCE.Do(_ReadTesting)

	if TESTING_ERR != nil {
		t.Fatalf(
			"read %s: %v",
			TESTING_FILE,
			TESTING_ERR,
		)
	}

	raw, ok := TESTING_KINDS[name]
	if !ok {
		t.Fatalf(
			"%s has no kind %q",
			TESTING_FILE,
			name,
		)
	}

	flat, err := _Flatten(raw)
	if err != nil {
		t.Fatalf(
			"flatten %s %q: %v",
			TESTING_FILE,
			name,
			err,
		)
	}

	if err := json.Unmarshal(
		flat,
		out,
	); err != nil {
		t.Fatalf(
			"parse %s %q: %v",
			TESTING_FILE,
			name,
			err,
		)
	}
}

// _Flatten rewrites the rows of one kind so that each row holds the expected octets of each
// variant as plain fields. A row has, for each variant, an object with the answer of pycrate
// ("py") and of Erlang ("er"), each hex text, {sha256, octets} or null. The expected answer
// is the one that "expected" names for the variant ("py", "er" or "derived", the octets in
// "derived"); with no name it is the answer that the oracles share, or the only one there is.
// The row then has "aper" and "uper" as hex text (short answers), and "aper_sha256",
// "aper_octets", "uper_sha256" and "uper_octets" for every answer. A variant with no answer
// has no fields. The object of the answers stays in "answers".
//
// Revisions:
//   - 2026-10-20 00:35: initial creation
func _Flatten(raw json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}

	if err := _FlattenNode(tree); err != nil {
		return nil, err
	}

	return json.Marshal(tree)
}

// _FlattenNode applies _Flatten to a node of the decoded tree and to everything below it.
//
// Revisions:
//   - 2026-10-20 00:35: initial creation
func _FlattenNode(node any) error {
	switch value := node.(type) {
	case []any:
		for _, item := range value {
			if err := _FlattenNode(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range value {
			if err := _FlattenNode(item); err != nil {
				return err
			}
		}

		return _FlattenRow(value)
	}

	return nil
}

// _FlattenRow gives one row the plain fields of its expected answers. A map that has no
// answers of both oracles is not a row and stays as it is.
//
// Revisions:
//   - 2026-10-20 00:35: initial creation
func _FlattenRow(row map[string]any) error {
	answers := map[string]any{}

	for _, variant := range []string{"aper", "uper"} {
		pair, ok := row[variant].(map[string]any)
		if !ok {
			return nil
		}

		if _, has := pair["py"]; !has {
			return nil
		}

		answers[variant] = pair
	}

	var (
		expected, _ = row["expected"].(map[string]any)
		derived, _  = row["derived"].(map[string]any)
	)

	for variant, pair := range answers {
		answer := pair.(map[string]any)["py"]
		if answer == nil {
			answer = pair.(map[string]any)["er"]
		}

		if name, ok := expected[variant].(string); ok {
			if name == "derived" {
				answer = derived[variant]
			} else {
				answer = pair.(map[string]any)[name]
			}
		}

		delete(
			row,
			variant,
		)

		if err := _FlattenAnswer(
			row,
			variant,
			answer,
		); err != nil {
			return err
		}
	}

	row["answers"] = answers

	return nil
}

// _FlattenAnswer sets the fields of one expected answer in a row: hex text and the digest
// for a short answer, the digest only for a long one.
//
// Revisions:
//   - 2026-10-20 00:35: initial creation
func _FlattenAnswer(
	row map[string]any,
	variant string,
	answer any,
) error {
	switch value := answer.(type) {
	case nil:
		return nil
	case string:
		data, err := hex.DecodeString(value)
		if err != nil {
			return err
		}

		sum := sha256.Sum256(data)
		row[variant] = value
		row[variant+"_sha256"] = hex.EncodeToString(sum[:])
		row[variant+"_octets"] = json.Number(strconv.Itoa(len(data)))
	case map[string]any:
		row[variant+"_sha256"] = value["sha256"]
		row[variant+"_octets"] = value["octets"]
	default:
		return fmt.Errorf(
			"answer of %s is %T",
			variant,
			answer,
		)
	}

	return nil
}

// _ReadTesting reads testing/testing.json into TESTING_KINDS, or the error into
// TESTING_ERR. TESTING_ONCE calls it.
//
// Revisions:
//   - 2026-10-20 00:21: initial creation
func _ReadTesting() {
	data, err := os.ReadFile(filepath.Join(
		"testing",
		TESTING_FILE,
	))
	if err != nil {
		TESTING_ERR = err

		return
	}

	TESTING_ERR = json.Unmarshal(
		data,
		&TESTING_KINDS,
	)
}

// _Check compares the octets that the code encoded in one variant with the octets that the
// vector expects. It returns the octets to decode: the expected octets of a short answer,
// or the encoded octets of a long answer once the sha256 and the length match.
//
// Revisions:
//   - 2026-10-20 00:21: initial creation
func (e *_Expected) _Check(
	t *testing.T,
	aligned bool,
	got []byte,
) []byte {
	t.Helper()

	var (
		hexed = _Both(
			e.Aper,
			e.Uper,
		)[aligned]
		digest = _Both(
			e.AperSha256,
			e.UperSha256,
		)[aligned]
		octets = map[bool]int{
			true:  e.AperOctets,
			false: e.UperOctets,
		}[aligned]
	)

	if digest == "" {
		want := _Unhex(
			t,
			hexed,
		)
		_Compare(
			t,
			got,
			want,
		)

		return want
	}

	sum := sha256.Sum256(got)
	if text := hex.EncodeToString(sum[:]); text != digest || len(got) != octets {
		t.Fatalf(
			"%d octets, sha256 %s, want %d, %s",
			len(got),
			text,
			octets,
			digest,
		)
	}

	return got
}

// _Unhex turns a vector's expected output into the bytes it names.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Unhex(
	t *testing.T,
	text string,
) []byte {
	t.Helper()

	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf(
			"decode %q: %v",
			text,
			err,
		)
	}

	return data
}

// _Compare reports an encoding that differs from the vector's.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Compare(
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
			"encoded % x, want % x",
			got,
			want,
		)
	}
}

// _Constraint builds the _Constraint a vector describes.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Constraint(
	lb,
	ub *int64,
	ext *bool,
) *per.Constraint {
	var size *per.Constraint

	switch {
	case lb != nil && ub != nil:
		size = per.Constrained(
			*lb,
			*ub,
		)
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

// _Show renders an optional bound for a subtest name.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Show[T any](value *T) string {
	if value == nil {
		return "nil"
	}

	return fmt.Sprintf(
		"%v",
		*value,
	)
}

// _SizeName builds the subtest name of a length-constrained vector.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _SizeName(
	kind string,
	in *_SizeInput,
	aligned bool,
) string {
	return fmt.Sprintf(
		"%s_len_%d_lb_%s_ub_%s_aligned_%v_ext_%s",
		kind,
		in.Length,
		_Show(in.Lb),
		_Show(in.Ub),
		aligned,
		_Show(in.Ext),
	)
}

// _Octets builds the octet string of the given length that the vectors describe.
//
// Revisions:
//   - 2026-02-06 16:21: initial creation as GenOctetString
func _Octets(length uint64) []byte {
	data := make(
		[]byte,
		length,
	)
	for i := range data {
		data[i] = byte(i % 256)
	}

	return data
}

// _Bitstring builds the alternating bit string of the given length that the
// vectors describe.
//
// Revisions:
//   - 2026-02-06 16:21: initial creation as GenBitString
func _Bitstring(length uint64) *asn1.BitString {
	data := make(
		[]byte,
		(length+7)/8,
	)
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

// _AsReal parses a vector's value, which is a number or the name of one of the
// values IEEE 754 has no literal for.
//
// Revisions:
//   - 2026-02-06 16:21: initial creation as parseRealValue
func _AsReal(
	t *testing.T,
	raw json.RawMessage,
) float64 {
	t.Helper()

	var name string
	if err := json.Unmarshal(
		raw,
		&name,
	); err == nil {
		switch name {
		case "Inf":
			return math.Inf(1)
		case "-Inf":
			return math.Inf(-1)
		case "NaN":
			return math.NaN()
		case "-0":
			return math.Copysign(
				0,
				-1,
			)
		default:
			t.Fatalf(
				"unknown special real %q",
				name,
			)
		}
	}

	var value float64
	if err := json.Unmarshal(
		raw,
		&value,
	); err != nil {
		t.Fatalf(
			"parse real %s: %v",
			raw,
			err,
		)
	}

	return value
}

// _SameReal compares two reals, counting two NaNs as equal and distinguishing
// the two zeroes, neither of which == does.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _SameReal(
	got,
	want float64,
) bool {
	if math.IsNaN(want) {
		return math.IsNaN(got)
	}

	if want == 0 {
		return got == 0 && math.Signbit(got) == math.Signbit(want)
	}

	return got == want
}
