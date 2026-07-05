package builtin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// YEAR_MONTH_ENCODING_TC represents a single YearMonthEncoding test case
// from year_month_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/year_month_encoding.py.
type YEAR_MONTH_ENCODING_TC struct {
	Input struct {
		Year  int64 `json:"year"`
		Month int64 `json:"month"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func loadYearMonthEncodingTestCases(t *testing.T) []YEAR_MONTH_ENCODING_TC {
	t.Helper()
	path := filepath.Join("testing", "year_month_encoding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []YEAR_MONTH_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}
	return tests
}

func TestMarshalYearMonthEncoding(t *testing.T) {
	tests := loadYearMonthEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_MONTH_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Month, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := YearMonthEncoding{
				Year:  NewYearEncoding(yearEncodingChoiceForYear(tc.Input.Year)),
				Month: tc.Input.Month,
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

func TestUnmarshalYearMonthEncoding(t *testing.T) {
	tests := loadYearMonthEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_MONTH_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Month, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value YearMonthEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year.Year() != tc.Input.Year {
				t.Errorf("Year.Year() = %d, expected %d", value.Year.Year(), tc.Input.Year)
			}
			if value.Month != tc.Input.Month {
				t.Errorf("Month = %d, expected %d", value.Month, tc.Input.Month)
			}
		})
	}
}
