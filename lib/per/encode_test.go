package per

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
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
