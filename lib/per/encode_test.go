package per

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dref dereferences a pointer and returns its string representation.
// If the pointer is nil, returns "NIL".
func dref[T any](ptr *T) string {
	if ptr == nil {
		return "NIL"
	}
	return fmt.Sprintf("%v", *ptr)
}

// BOOL represents a single test case from the JSON file
type BOOL struct {
	Input   bool   `json:"input"`
	Aligned bool   `json:"aligned"`
	Output  string `json:"output"`
}

func TestWriteBool(t *testing.T) {
	// Load test data from testing/bool.json
	path := filepath.Join("testing", "bool.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []BOOL
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		name := strings.ToUpper(fmt.Sprintf("BOOL_VALUE_%v_ALIGNED_%v", tc.Input, tc.Aligned))
		t.Run(name, func(t *testing.T) {
			// Decode expected output from hex string
			expected, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode expected output hex: %v", err)
			}

			// Create encoder
			encoder := NewEncoder(tc.Aligned)

			// Encode the boolean value
			err = encoder.EncodeBoolean(tc.Input)
			if err != nil {
				t.Errorf("EncodeBoolean() error = %v", err)
				return
			}

			// Get the encoded bytes
			result := encoder.Bytes()

			// Compare with expected output
			if len(result) != len(expected) {
				t.Errorf("EncodeBoolean() returned %d bytes, expected %d", len(result), len(expected))
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("EncodeBoolean() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}

// INT represents a single integer test case from the JSON file
type INT struct {
	Input struct {
		Value      int64  `json:"value"`
		Lb         *int64 `json:"lb"`
		Ub         *int64 `json:"ub"`
		Extensible *bool  `json:"extensible"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func TestWriteInteger(t *testing.T) {
	// Load test data from testing/integer.json
	path := filepath.Join("testing", "integer.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []INT
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		name := strings.ToUpper(fmt.Sprintf("INTEGER_VALUE_%d_LB_%s_UB_%s_ALIGNED_%v_EXTENSIBLE_%s",
			tc.Input.Value, dref(tc.Input.Lb), dref(tc.Input.Ub), tc.Aligned, dref(tc.Input.Extensible)))
		t.Run(name, func(t *testing.T) {
			// Decode expected output from hex string
			expected, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode expected output hex: %v", err)
			}

			// Create encoder
			encoder := NewEncoder(tc.Aligned)

			// Handle nullable Extensible field - treat null as false
			extensible := false
			if tc.Input.Extensible != nil {
				extensible = *tc.Input.Extensible
			}

			// Encode the integer value with constraints
			err = encoder.EncodeInteger(tc.Input.Value, tc.Input.Lb, tc.Input.Ub, extensible)
			if err != nil {
				t.Errorf("EncodeInteger() error = %v", err)
				return
			}

			// Get the encoded bytes
			result := encoder.Bytes()

			// Compare with expected output
			if len(result) != len(expected) {
				t.Errorf("EncodeInteger() returned %d bytes, expected %d", len(result), len(expected))
				t.Logf("Expected: %x", expected)
				t.Logf("Got:      %x", result)
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("EncodeInteger() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}

// OCT_STR represents a single octet string test case from the JSON file
type OCT_STR struct {
	Input struct {
		Length     uint64  `json:"length"`
		Lb         *uint64 `json:"lb"`
		Ub         *uint64 `json:"ub"`
		Extensible *bool   `json:"extensible"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func GenOctetString(length uint64) []byte {
	pattern := make([]byte, 256)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	result := make([]byte, length)
	for i := range length {
		result[i] = pattern[i%uint64(len(pattern))]
	}
	return result
}

func GenBitString(length uint64) *asn1.BitString {
	// Generate alternating bits: 0, 1, 0, 1, ...
	num := new(big.Int)
	buf := make([]byte, (length+7)/8)
	for i := range length {
		num.Lsh(num, 1)
		num.SetBit(num, 0, uint(i%2))
	}
	// Left-align: BitString.Bytes stores bits at MSB, so pad right
	num.Lsh(num, uint((8-length%8)%8))
	num.FillBytes(buf)
	return &asn1.BitString{
		Bytes:     buf,
		BitLength: int(length),
	}
}

func TestWriteOctetString(t *testing.T) {
	// Load test data from testing/octet_string.json
	path := filepath.Join("testing", "octet_string.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []OCT_STR
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		name := strings.ToUpper(fmt.Sprintf("OCTET_STRING_LENGTH_%d_LB_%s_UB_%s_ALIGNED_%v_EXTENSIBLE_%s",
			tc.Input.Length, dref(tc.Input.Lb), dref(tc.Input.Ub), tc.Aligned, dref(tc.Input.Extensible)))
		t.Run(name, func(t *testing.T) {
			// Decode expected output from hex string
			expected, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode expected output hex: %v", err)
			}

			// Create encoder
			encoder := NewEncoder(tc.Aligned)

			// Handle nullable Extensible field - treat null as false
			extensible := false
			if tc.Input.Extensible != nil {
				extensible = *tc.Input.Extensible
			}

			// Generate the octet string value
			value := GenOctetString(tc.Input.Length)

			// Encode the octet string value with constraints
			err = encoder.EncodeOctetString(value, tc.Input.Lb, tc.Input.Ub, extensible)
			if err != nil {
				t.Errorf("EncodeOctetString() error = %v", err)
				return
			}

			// Get the encoded bytes
			result := encoder.Bytes()

			// Compare with expected output
			if len(result) != len(expected) {
				t.Errorf("EncodeOctetString() returned %d bytes, expected %d", len(result), len(expected))
				t.Logf("Expected: %x", expected)
				t.Logf("Got:      %x", result)
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("EncodeOctetString() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}

// BIT_STR represents a single bit string test case from the JSON file
type BIT_STR struct {
	Input struct {
		Length     uint64  `json:"length"`
		Lb         *uint64 `json:"lb"`
		Ub         *uint64 `json:"ub"`
		Extensible *bool   `json:"extensible"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func TestWriteBitString(t *testing.T) {
	// Load test data from testing/bit_string.json
	path := filepath.Join("testing", "bit_string.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []BIT_STR
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		name := strings.ToUpper(fmt.Sprintf("BIT_STRING_LENGTH_%d_LB_%s_UB_%s_ALIGNED_%v_EXTENSIBLE_%s",
			tc.Input.Length, dref(tc.Input.Lb), dref(tc.Input.Ub), tc.Aligned, dref(tc.Input.Extensible)))
		t.Run(name, func(t *testing.T) {
			// Decode expected output from hex string
			expected, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode expected output hex: %v", err)
			}

			// Create encoder
			encoder := NewEncoder(tc.Aligned)

			// Handle nullable Extensible field - treat null as false
			extensible := false
			if tc.Input.Extensible != nil {
				extensible = *tc.Input.Extensible
			}

			// Generate the bit string value
			value := GenBitString(tc.Input.Length)

			// Encode the bit string value with constraints
			err = encoder.EncodeBitString(value, tc.Input.Lb, tc.Input.Ub, extensible)
			if err != nil {
				t.Errorf("EncodeBitString() error = %v", err)
				return
			}

			// Get the encoded bytes
			result := encoder.Bytes()

			// Compare with expected output
			if len(result) != len(expected) {
				t.Errorf("EncodeBitString() returned %d bytes, expected %d", len(result), len(expected))
				t.Logf("Expected: %x", expected)
				t.Logf("Got:      %x", result)
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("EncodeBitString() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}

// ENUM represents a single enumerated test case from the JSON file
type ENUM struct {
	Input struct {
		Value      uint64 `json:"value"`
		Count      uint64 `json:"count"`
		Extensible bool   `json:"extensible"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func TestWriteEnumerated(t *testing.T) {
	path := filepath.Join("testing", "enumerated.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ENUM
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		name := strings.ToUpper(fmt.Sprintf("ENUMERATED_VALUE_%d_COUNT_%d_ALIGNED_%v_EXTENSIBLE_%v",
			tc.Input.Value, tc.Input.Count, tc.Aligned, tc.Input.Extensible))
		t.Run(name, func(t *testing.T) {
			expected, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode expected output hex: %v", err)
			}

			encoder := NewEncoder(tc.Aligned)

			err = encoder.EncodeEnumerated(tc.Input.Value, tc.Input.Count, tc.Input.Extensible)
			if err != nil {
				t.Errorf("EncodeEnumerated() error = %v", err)
				return
			}

			result := encoder.Bytes()

			if len(result) != len(expected) {
				t.Errorf("EncodeEnumerated() returned %d bytes, expected %d", len(result), len(expected))
				t.Logf("Expected: %x", expected)
				t.Logf("Got:      %x", result)
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("EncodeEnumerated() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}

// REAL_TC represents a single real test case from the JSON file.
// The Value field may be a float64 or a string for special values (NaN, Inf, -Inf, -0).
type REAL_TC struct {
	Input struct {
		Value json.RawMessage `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// parseRealValue parses a REAL test case value which can be a float64 or a string.
func parseRealValue(raw json.RawMessage) (float64, error) {
	// Try parsing as a string first (for special values)
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch s {
		case "Inf":
			return math.Inf(1), nil
		case "-Inf":
			return math.Inf(-1), nil
		case "NaN":
			return math.NaN(), nil
		case "-0":
			return math.Copysign(0, -1), nil
		default:
			return 0, fmt.Errorf("unknown special value: %s", s)
		}
	}

	// Parse as float64
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, err
	}
	return f, nil
}

func realValueLabel(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return fmt.Sprintf("%g", f)
	}
	return string(raw)
}

func TestWriteReal(t *testing.T) {
	path := filepath.Join("testing", "real.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []REAL_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		label := realValueLabel(tc.Input.Value)
		name := strings.ToUpper(fmt.Sprintf("REAL_VALUE_%s_ALIGNED_%v", label, tc.Aligned))
		t.Run(name, func(t *testing.T) {
			expected, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode expected output hex: %v", err)
			}

			value, err := parseRealValue(tc.Input.Value)
			if err != nil {
				t.Fatalf("Failed to parse real value: %v", err)
			}

			encoder := NewEncoder(tc.Aligned)

			err = encoder.EncodeReal(value)
			if err != nil {
				t.Errorf("EncodeReal() error = %v", err)
				return
			}

			result := encoder.Bytes()

			if len(result) != len(expected) {
				t.Errorf("EncodeReal() returned %d bytes, expected %d", len(result), len(expected))
				t.Logf("Expected: %x", expected)
				t.Logf("Got:      %x", result)
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("EncodeReal() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}
