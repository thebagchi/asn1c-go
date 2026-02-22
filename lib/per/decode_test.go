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

func TestReadBool(t *testing.T) {
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
			// Decode hex string to bytes
			encodedData, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}

			// Create decoder
			decoder := NewDecoder(encodedData, tc.Aligned)

			// Decode the boolean value
			result, err := decoder.DecodeBoolean()
			if err != nil {
				t.Errorf("DecodeBoolean() error = %v", err)
				return
			}

			// Compare with expected input
			if result != tc.Input {
				t.Errorf("DecodeBoolean() = %v, expected %v", result, tc.Input)
			}
		})
	}
}

func TestReadInteger(t *testing.T) {
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
			// Decode hex string to bytes
			encodedData, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}

			// Create decoder
			decoder := NewDecoder(encodedData, tc.Aligned)

			// Handle nullable Extensible field - treat null as false
			extensible := false
			if tc.Input.Extensible != nil {
				extensible = *tc.Input.Extensible
			}

			// Decode the integer value with constraints
			result, err := decoder.DecodeInteger(tc.Input.Lb, tc.Input.Ub, extensible)
			if err != nil {
				t.Errorf("DecodeInteger() error = %v", err)
				return
			}

			// Compare with expected input value
			if result != tc.Input.Value {
				t.Errorf("DecodeInteger() = %d, expected %d", result, tc.Input.Value)
			}
		})
	}
}

func TestReadOctetString(t *testing.T) {
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
			// Decode hex string to bytes
			encodedData, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}

			// Create decoder
			decoder := NewDecoder(encodedData, tc.Aligned)

			// Handle nullable Extensible field - treat null as false
			extensible := false
			if tc.Input.Extensible != nil {
				extensible = *tc.Input.Extensible
			}

			// Decode the octet string value with constraints
			result, err := decoder.DecodeOctetString(tc.Input.Lb, tc.Input.Ub, extensible)
			if err != nil {
				t.Errorf("DecodeOctetString() error = %v", err)
				return
			}

			// Generate expected octet string value
			expected := GenOctetString(tc.Input.Length)

			// Compare with expected value
			if len(result) != len(expected) {
				t.Errorf("DecodeOctetString() returned %d bytes, expected %d", len(result), len(expected))
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("DecodeOctetString() at position %d = %02x, expected %02x", i, result[i], expected[i])
				}
			}
		})
	}
}
