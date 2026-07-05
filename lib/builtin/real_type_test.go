package builtin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// REAL_TYPE_TC represents a single RealType test case from real_type.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see lib/builtin/testing/real_type.py.
type REAL_TYPE_TC struct {
	Input struct {
		Mantissa int64 `json:"mantissa"`
		Base     int64 `json:"base"`
		Exponent int64 `json:"exponent"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func loadRealTypeTestCases(t *testing.T) []REAL_TYPE_TC {
	t.Helper()
	path := filepath.Join("testing", "real_type.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []REAL_TYPE_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}
	return tests
}

func TestMarshalRealType(t *testing.T) {
	tests := loadRealTypeTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("MANTISSA_%d_BASE_%d_EXPONENT_%d_ALIGNED_%v",
			tc.Input.Mantissa, tc.Input.Base, tc.Input.Exponent, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := RealType{
				Mantissa: tc.Input.Mantissa,
				Base:     tc.Input.Base,
				Exponent: tc.Input.Exponent,
			}

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

func TestUnmarshalRealType(t *testing.T) {
	tests := loadRealTypeTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("MANTISSA_%d_BASE_%d_EXPONENT_%d_ALIGNED_%v",
			tc.Input.Mantissa, tc.Input.Base, tc.Input.Exponent, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value RealType
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Mantissa != tc.Input.Mantissa {
				t.Errorf("Mantissa = %d, expected %d", value.Mantissa, tc.Input.Mantissa)
			}
			if value.Base != tc.Input.Base {
				t.Errorf("Base = %d, expected %d", value.Base, tc.Input.Base)
			}
			if value.Exponent != tc.Input.Exponent {
				t.Errorf("Exponent = %d, expected %d", value.Exponent, tc.Input.Exponent)
			}
		})
	}
}
