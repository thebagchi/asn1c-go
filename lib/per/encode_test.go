package per

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BOOL represents a single test case from the JSON file
type BOOL struct {
	Input   bool   `json:"input"`
	Aligned bool   `json:"aligned"`
	Output  string `json:"output"`
}

func TestWriteBool(t *testing.T) {
	// Load test data from testing/bool.json
	testDataPath := filepath.Join("testing", "bool.json")
	data, err := os.ReadFile(testDataPath)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []BOOL
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("input=%v_aligned=%v", tc.Input, tc.Aligned), func(t *testing.T) {
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
