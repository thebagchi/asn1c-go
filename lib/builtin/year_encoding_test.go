package builtin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// YEAR_ENCODING_TC represents a single YearEncoding test case from
// year_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/year_encoding.py.
type YEAR_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// yearEncodingChoiceForYear picks the CHOICE alternative matching the given
// year value (X.691 clause 32.2.3), for tests that just have a plain year
// integer and don't want to work out the alternative boundaries themselves.
func yearEncodingChoiceForYear(year int64) choiceYearEncoding {
	switch {
	case year >= 2005 && year <= 2020:
		value := YearEncoding_Immediate(year)
		return &value
	case year >= 2021 && year <= 2276:
		value := YearEncoding_NearFuture(year)
		return &value
	case year >= 1749 && year <= 2004:
		value := YearEncoding_NearPast(year)
		return &value
	default:
		value := YearEncoding_Remainder(year)
		return &value
	}
}

func loadYearEncodingTestCases(t *testing.T) []YEAR_ENCODING_TC {
	t.Helper()
	path := filepath.Join("testing", "year_encoding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []YEAR_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}
	return tests
}

func TestMarshalYearEncoding(t *testing.T) {
	tests := loadYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := NewYearEncoding(yearEncodingChoiceForYear(tc.Input.Value))

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

func TestUnmarshalYearEncoding(t *testing.T) {
	tests := loadYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value YearEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year() != tc.Input.Value {
				t.Errorf("Year() = %d, expected %d", value.Year(), tc.Input.Value)
			}
		})
	}
}
