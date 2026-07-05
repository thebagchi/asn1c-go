package builtin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// CENTURY_ENCODING_TC represents a single CenturyEncoding test case from
// century_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/century_encoding.py.
type CENTURY_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func loadCenturyEncodingTestCases(t *testing.T) []CENTURY_ENCODING_TC {
	t.Helper()
	path := filepath.Join("testing", "century_encoding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []CENTURY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}
	return tests
}

func TestMarshalCenturyEncoding(t *testing.T) {
	tests := loadCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := CenturyEncoding(tc.Input.Value)

			var (
				result []byte
				err    error
			)
			if tc.Aligned {
				result, err = value.MarshalAPER()
			} else {
				result, err = value.MarshalUPER()
			}
			if err != nil {
				t.Fatalf("Marshal error = %v", err)
			}

			if hex.EncodeToString(result) != tc.Output {
				t.Errorf("Marshal() = %x, expected %s", result, tc.Output)
			}
		})
	}
}

func TestUnmarshalCenturyEncoding(t *testing.T) {
	tests := loadCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value CenturyEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value) != tc.Input.Value {
				t.Errorf("Value = %d, expected %d", value, tc.Input.Value)
			}
		})
	}
}
