package builtin_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/thebagchi/asn1c-go/builtin"
)

// ANY_CENTURY_ENCODING_TC represents a single AnyCenturyEncoding test case
// from any_century_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/any_century_encoding.py.
type ANY_CENTURY_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadAnyCenturyEncodingTestCases reads the vectors for AnyCenturyEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadAnyCenturyEncodingTestCases(t *testing.T) []ANY_CENTURY_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "any_century_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ANY_CENTURY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalAnyCenturyEncoding checks that AnyCenturyEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalAnyCenturyEncoding(t *testing.T) {
	tests := loadAnyCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := builtin.AnyCenturyEncoding(tc.Input.Value)

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

// TestUnmarshalAnyCenturyEncoding checks that AnyCenturyEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalAnyCenturyEncoding(t *testing.T) {
	tests := loadAnyCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.AnyCenturyEncoding
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

// ANY_YEAR_ENCODING_TC represents a single AnyYearEncoding test case from
// any_year_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/any_year_encoding.py.
type ANY_YEAR_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadAnyYearEncodingTestCases reads the vectors for AnyYearEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadAnyYearEncodingTestCases(t *testing.T) []ANY_YEAR_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "any_year_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ANY_YEAR_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalAnyYearEncoding checks that AnyYearEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalAnyYearEncoding(t *testing.T) {
	tests := loadAnyYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := builtin.AnyYearEncoding(tc.Input.Value)

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

// TestUnmarshalAnyYearEncoding checks that AnyYearEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalAnyYearEncoding(t *testing.T) {
	tests := loadAnyYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.AnyYearEncoding
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

// CENTURY_ENCODING_TC represents a single CenturyEncoding test case from
// century_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/century_encoding.py.
type CENTURY_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadCenturyEncodingTestCases reads the vectors for CenturyEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
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

// TestMarshalCenturyEncoding checks that CenturyEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalCenturyEncoding(t *testing.T) {
	tests := loadCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := builtin.CenturyEncoding(tc.Input.Value)

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

// TestUnmarshalCenturyEncoding checks that CenturyEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalCenturyEncoding(t *testing.T) {
	tests := loadCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.CenturyEncoding
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

// REAL_TYPE_TC represents a single RealType test case from real_type.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see builtin/testing/real_type.py.
type REAL_TYPE_TC struct {
	Input struct {
		Mantissa int64 `json:"mantissa"`
		Base     int64 `json:"base"`
		Exponent int64 `json:"exponent"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadRealTypeTestCases reads the vectors for RealType.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
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

// TestMarshalRealType checks that RealType encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalRealType(t *testing.T) {
	tests := loadRealTypeTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("MANTISSA_%d_BASE_%d_EXPONENT_%d_ALIGNED_%v",
			tc.Input.Mantissa, tc.Input.Base, tc.Input.Exponent, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := builtin.RealType{
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

// TestUnmarshalRealType checks that RealType decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
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

			var value builtin.RealType
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Mantissa != tc.Input.Mantissa {
				t.Errorf(
					"Mantissa = %d, expected %d",
					value.Mantissa,
					tc.Input.Mantissa,
				)
			}

			if value.Base != tc.Input.Base {
				t.Errorf("Base = %d, expected %d", value.Base, tc.Input.Base)
			}

			if value.Exponent != tc.Input.Exponent {
				t.Errorf(
					"Exponent = %d, expected %d",
					value.Exponent,
					tc.Input.Exponent,
				)
			}
		})
	}
}

// YEAR_ENCODING_TC represents a single YearEncoding test case from
// year_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/year_encoding.py.
type YEAR_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// yearEncodingForYear builds the YEAR-ENCODING whose CHOICE alternative matches
// the given year (X.691 clause 32.2.3), for cases that have a plain year and do
// not want to work out the alternative boundaries themselves.
//
// It returns the wrapper rather than the alternative because the interface the
// alternatives implement is sealed, and an external test cannot name it.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
//   - 2026-09-22 06:43: returns *builtin.YearEncoding, so that the test can live
//     in builtin_test and reach the package through its public surface
func yearEncodingForYear(year int64) *builtin.YearEncoding {
	switch {
	case year >= 2005 && year <= 2020:
		value := builtin.YearEncoding_Immediate(year)
		return builtin.NewYearEncoding(&value)
	case year >= 2021 && year <= 2276:
		value := builtin.YearEncoding_NearFuture(year)
		return builtin.NewYearEncoding(&value)
	case year >= 1749 && year <= 2004:
		value := builtin.YearEncoding_NearPast(year)
		return builtin.NewYearEncoding(&value)
	default:
		value := builtin.YearEncoding_Remainder(year)
		return builtin.NewYearEncoding(&value)
	}
}

// loadYearEncodingTestCases reads the vectors for YearEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
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

// TestMarshalYearEncoding checks that YearEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalYearEncoding(t *testing.T) {
	tests := loadYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := yearEncodingForYear((tc.Input.Value))

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

// TestUnmarshalYearEncoding checks that YearEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalYearEncoding(t *testing.T) {
	tests := loadYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.YearEncoding
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

// YEAR_MONTH_ENCODING_TC represents a single YearMonthEncoding test case
// from year_month_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/year_month_encoding.py.
type YEAR_MONTH_ENCODING_TC struct {
	Input struct {
		Year  int64 `json:"year"`
		Month int64 `json:"month"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadYearMonthEncodingTestCases reads the vectors for YearMonthEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
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

// TestMarshalYearMonthEncoding checks that YearMonthEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalYearMonthEncoding(t *testing.T) {
	tests := loadYearMonthEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_MONTH_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Month,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.YearMonthEncoding{
				Year:  yearEncodingForYear((tc.Input.Year)),
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

// TestUnmarshalYearMonthEncoding checks that YearMonthEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalYearMonthEncoding(t *testing.T) {
	tests := loadYearMonthEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_MONTH_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Month,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.YearMonthEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year.Year() != tc.Input.Year {
				t.Errorf(
					"Year.Year() = %d, expected %d",
					value.Year.Year(),
					tc.Input.Year,
				)
			}

			if value.Month != tc.Input.Month {
				t.Errorf("Month = %d, expected %d", value.Month, tc.Input.Month)
			}
		})
	}
}

// ANY_DATE_ENCODING_TC represents a single AnyDateEncoding test case from
// any_date_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/any_date_encoding.py.
type ANY_DATE_ENCODING_TC struct {
	Input struct {
		Year  int64 `json:"year"`
		Month int64 `json:"month"`
		Day   int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadAnyDateEncodingTestCases reads the vectors for AnyDateEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadAnyDateEncodingTestCases(t *testing.T) []ANY_DATE_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "any_date_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ANY_DATE_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalAnyDateEncoding checks that AnyDateEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalAnyDateEncoding(t *testing.T) {
	tests := loadAnyDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Month,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.AnyDateEncoding{
				Year:  builtin.AnyYearEncoding(tc.Input.Year),
				Month: tc.Input.Month,
				Day:   tc.Input.Day,
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

// TestUnmarshalAnyDateEncoding checks that AnyDateEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalAnyDateEncoding(t *testing.T) {
	tests := loadAnyDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Month,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.AnyDateEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value.Year) != tc.Input.Year {
				t.Errorf("Year = %d, expected %d", value.Year, tc.Input.Year)
			}

			if value.Month != tc.Input.Month {
				t.Errorf("Month = %d, expected %d", value.Month, tc.Input.Month)
			}

			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}

// ANY_YEAR_DAY_ENCODING_TC represents a single AnyYearDayEncoding test case
// from any_year_day_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/any_year_day_encoding.py.
type ANY_YEAR_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadAnyYearDayEncodingTestCases reads the vectors for AnyYearDayEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadAnyYearDayEncodingTestCases(t *testing.T) []ANY_YEAR_DAY_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "any_year_day_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ANY_YEAR_DAY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalAnyYearDayEncoding checks that AnyYearDayEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalAnyYearDayEncoding(t *testing.T) {
	tests := loadAnyYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.AnyYearDayEncoding{
				Year: builtin.AnyYearEncoding(tc.Input.Year),
				Day:  tc.Input.Day,
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

// TestUnmarshalAnyYearDayEncoding checks that AnyYearDayEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalAnyYearDayEncoding(t *testing.T) {
	tests := loadAnyYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.AnyYearDayEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value.Year) != tc.Input.Year {
				t.Errorf("Year = %d, expected %d", value.Year, tc.Input.Year)
			}

			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}

// ANY_YEAR_WEEK_DAY_ENCODING_TC represents a single AnyYearWeekDayEncoding
// test case from any_year_week_day_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/any_year_week_day_encoding.py.
type ANY_YEAR_WEEK_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadAnyYearWeekDayEncodingTestCases reads the vectors for AnyYearWeekDayEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadAnyYearWeekDayEncodingTestCases(t *testing.T) []ANY_YEAR_WEEK_DAY_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "any_year_week_day_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ANY_YEAR_WEEK_DAY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalAnyYearWeekDayEncoding checks that AnyYearWeekDayEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalAnyYearWeekDayEncoding(t *testing.T) {
	tests := loadAnyYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.AnyYearWeekDayEncoding{
				Year: builtin.AnyYearEncoding(tc.Input.Year),
				Week: tc.Input.Week,
				Day:  tc.Input.Day,
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

// TestUnmarshalAnyYearWeekDayEncoding checks that AnyYearWeekDayEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalAnyYearWeekDayEncoding(t *testing.T) {
	tests := loadAnyYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.AnyYearWeekDayEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value.Year) != tc.Input.Year {
				t.Errorf("Year = %d, expected %d", value.Year, tc.Input.Year)
			}

			if value.Week != tc.Input.Week {
				t.Errorf("Week = %d, expected %d", value.Week, tc.Input.Week)
			}

			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}

// ANY_YEAR_WEEK_ENCODING_TC represents a single AnyYearWeekEncoding test
// case from any_year_week_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/any_year_week_encoding.py.
type ANY_YEAR_WEEK_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadAnyYearWeekEncodingTestCases reads the vectors for AnyYearWeekEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadAnyYearWeekEncodingTestCases(t *testing.T) []ANY_YEAR_WEEK_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "any_year_week_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []ANY_YEAR_WEEK_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalAnyYearWeekEncoding checks that AnyYearWeekEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalAnyYearWeekEncoding(t *testing.T) {
	tests := loadAnyYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.AnyYearWeekEncoding{
				Year: builtin.AnyYearEncoding(tc.Input.Year),
				Week: tc.Input.Week,
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

// TestUnmarshalAnyYearWeekEncoding checks that AnyYearWeekEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalAnyYearWeekEncoding(t *testing.T) {
	tests := loadAnyYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.AnyYearWeekEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value.Year) != tc.Input.Year {
				t.Errorf("Year = %d, expected %d", value.Year, tc.Input.Year)
			}

			if value.Week != tc.Input.Week {
				t.Errorf("Week = %d, expected %d", value.Week, tc.Input.Week)
			}
		})
	}
}

// DATE_ENCODING_TC represents a single DateEncoding test case from
// date_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/date_encoding.py.
type DATE_ENCODING_TC struct {
	Input struct {
		Year  int64 `json:"year"`
		Month int64 `json:"month"`
		Day   int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadDateEncodingTestCases reads the vectors for DateEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadDateEncodingTestCases(t *testing.T) []DATE_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "date_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []DATE_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalDateEncoding checks that DateEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalDateEncoding(t *testing.T) {
	tests := loadDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Month,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.DateEncoding{
				Year:  yearEncodingForYear((tc.Input.Year)),
				Month: tc.Input.Month,
				Day:   tc.Input.Day,
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

// TestUnmarshalDateEncoding checks that DateEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalDateEncoding(t *testing.T) {
	tests := loadDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Month,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.DateEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year.Year() != tc.Input.Year {
				t.Errorf(
					"Year.Year() = %d, expected %d",
					value.Year.Year(),
					tc.Input.Year,
				)
			}

			if value.Month != tc.Input.Month {
				t.Errorf("Month = %d, expected %d", value.Month, tc.Input.Month)
			}

			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}

// DURATION_EQUIVALENT_TC represents a single DurationEquivalent test case
// from duration_equivalent.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/duration_equivalent.py.
type DURATION_EQUIVALENT_TC struct {
	Input struct {
		Years          *int64 `json:"years"`
		Months         *int64 `json:"months"`
		Weeks          *int64 `json:"weeks"`
		Days           *int64 `json:"days"`
		Hours          *int64 `json:"hours"`
		Minutes        *int64 `json:"minutes"`
		Seconds        *int64 `json:"seconds"`
		FractionalPart *struct {
			NumberOfDigits  int64 `json:"number-of-digits"`
			FractionalValue int64 `json:"fractional-value"`
		} `json:"fractional-part"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadDurationEquivalentTestCases reads the vectors for DurationEquivalent.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadDurationEquivalentTestCases(t *testing.T) []DURATION_EQUIVALENT_TC {
	t.Helper()

	path := filepath.Join("testing", "duration_equivalent.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []DURATION_EQUIVALENT_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// durationEquivalentFromTC is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func durationEquivalentFromTC(tc DURATION_EQUIVALENT_TC) builtin.DurationEquivalent {
	value := builtin.DurationEquivalent{
		Years:   tc.Input.Years,
		Months:  tc.Input.Months,
		Weeks:   tc.Input.Weeks,
		Days:    tc.Input.Days,
		Hours:   tc.Input.Hours,
		Minutes: tc.Input.Minutes,
		Seconds: tc.Input.Seconds,
	}
	if tc.Input.FractionalPart != nil {
		value.FractionalPart = &builtin.DurationEquivalent_FractionalPart{
			NumberOfDigits:  tc.Input.FractionalPart.NumberOfDigits,
			FractionalValue: tc.Input.FractionalPart.FractionalValue,
		}
	}

	return value
}

// TestMarshalDurationEquivalent checks that DurationEquivalent encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalDurationEquivalent(t *testing.T) {
	tests := loadDurationEquivalentTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v",
			intLabel(tc.Input.Years),
			intLabel(tc.Input.Months),
			intLabel(tc.Input.Weeks),
			intLabel(tc.Input.Days),
			intLabel(tc.Input.Hours),
			intLabel(tc.Input.Minutes),
			intLabel(tc.Input.Seconds),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := durationEquivalentFromTC(tc)

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

// TestUnmarshalDurationEquivalent checks that DurationEquivalent decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalDurationEquivalent(t *testing.T) {
	tests := loadDurationEquivalentTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v",
			intLabel(tc.Input.Years),
			intLabel(tc.Input.Months),
			intLabel(tc.Input.Weeks),
			intLabel(tc.Input.Days),
			intLabel(tc.Input.Hours),
			intLabel(tc.Input.Minutes),
			intLabel(tc.Input.Seconds),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.DurationEquivalent
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			expected := durationEquivalentFromTC(tc)

			checkOptInt64(t, "Years", value.Years, expected.Years)
			checkOptInt64(t, "Months", value.Months, expected.Months)
			checkOptInt64(t, "Weeks", value.Weeks, expected.Weeks)
			checkOptInt64(t, "Days", value.Days, expected.Days)
			checkOptInt64(t, "Hours", value.Hours, expected.Hours)
			checkOptInt64(t, "Minutes", value.Minutes, expected.Minutes)
			checkOptInt64(t, "Seconds", value.Seconds, expected.Seconds)

			if (value.FractionalPart == nil) != (expected.FractionalPart == nil) {
				t.Errorf(
					"FractionalPart presence = %v, expected %v",
					value.FractionalPart != nil,
					expected.FractionalPart != nil,
				)
			} else if value.FractionalPart != nil {
				part, wanted := value.FractionalPart, expected.FractionalPart

				if part.NumberOfDigits != wanted.NumberOfDigits {
					t.Errorf(
						"FractionalPart.NumberOfDigits = %d, expected %d",
						part.NumberOfDigits,
						wanted.NumberOfDigits,
					)
				}

				if part.FractionalValue != wanted.FractionalValue {
					t.Errorf(
						"FractionalPart.FractionalValue = %d, expected %d",
						part.FractionalValue,
						wanted.FractionalValue,
					)
				}
			}
		})
	}
}

// DURATION_INTERVAL_ENCODING_TC represents a single DurationIntervalEncoding
// test case from duration_interval_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/duration_interval_encoding.py.
type DURATION_INTERVAL_ENCODING_TC struct {
	Input struct {
		Years          *int64 `json:"years"`
		Months         *int64 `json:"months"`
		Weeks          *int64 `json:"weeks"`
		Days           *int64 `json:"days"`
		Hours          *int64 `json:"hours"`
		Minutes        *int64 `json:"minutes"`
		Seconds        *int64 `json:"seconds"`
		FractionalPart *struct {
			NumberOfDigits  int64 `json:"number-of-digits"`
			FractionalValue int64 `json:"fractional-value"`
		} `json:"fractional-part"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadDurationIntervalEncodingTestCases reads the vectors for DurationIntervalEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadDurationIntervalEncodingTestCases(t *testing.T) []DURATION_INTERVAL_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "duration_interval_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []DURATION_INTERVAL_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// intLabel is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func intLabel(v *int64) string {
	if v == nil {
		return "NONE"
	}

	return fmt.Sprintf("%d", *v)
}

// durationIntervalEncodingFromTC is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func durationIntervalEncodingFromTC(
	tc DURATION_INTERVAL_ENCODING_TC,
) builtin.DurationIntervalEncoding {
	value := builtin.DurationIntervalEncoding{
		Years:   tc.Input.Years,
		Months:  tc.Input.Months,
		Weeks:   tc.Input.Weeks,
		Days:    tc.Input.Days,
		Hours:   tc.Input.Hours,
		Minutes: tc.Input.Minutes,
		Seconds: tc.Input.Seconds,
	}
	if tc.Input.FractionalPart != nil {
		value.FractionalPart = &builtin.DurationIntervalEncoding_FractionalPart{
			NumberOfDigits:  tc.Input.FractionalPart.NumberOfDigits,
			FractionalValue: tc.Input.FractionalPart.FractionalValue,
		}
	}

	return value
}

// TestMarshalDurationIntervalEncoding checks that DurationIntervalEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalDurationIntervalEncoding(t *testing.T) {
	tests := loadDurationIntervalEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v",
			intLabel(tc.Input.Years),
			intLabel(tc.Input.Months),
			intLabel(tc.Input.Weeks),
			intLabel(tc.Input.Days),
			intLabel(tc.Input.Hours),
			intLabel(tc.Input.Minutes),
			intLabel(tc.Input.Seconds),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := durationIntervalEncodingFromTC(tc)

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

// TestUnmarshalDurationIntervalEncoding checks that DurationIntervalEncoding decodes from its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalDurationIntervalEncoding(t *testing.T) {
	tests := loadDurationIntervalEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v",
			intLabel(tc.Input.Years),
			intLabel(tc.Input.Months),
			intLabel(tc.Input.Weeks),
			intLabel(tc.Input.Days),
			intLabel(tc.Input.Hours),
			intLabel(tc.Input.Minutes),
			intLabel(tc.Input.Seconds),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.DurationIntervalEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			expected := durationIntervalEncodingFromTC(tc)

			checkOptInt64(t, "Years", value.Years, expected.Years)
			checkOptInt64(t, "Months", value.Months, expected.Months)
			checkOptInt64(t, "Weeks", value.Weeks, expected.Weeks)
			checkOptInt64(t, "Days", value.Days, expected.Days)
			checkOptInt64(t, "Hours", value.Hours, expected.Hours)
			checkOptInt64(t, "Minutes", value.Minutes, expected.Minutes)
			checkOptInt64(t, "Seconds", value.Seconds, expected.Seconds)

			if (value.FractionalPart == nil) != (expected.FractionalPart == nil) {
				t.Errorf(
					"FractionalPart presence = %v, expected %v",
					value.FractionalPart != nil,
					expected.FractionalPart != nil,
				)
			} else if value.FractionalPart != nil {
				part, wanted := value.FractionalPart, expected.FractionalPart

				if part.NumberOfDigits != wanted.NumberOfDigits {
					t.Errorf(
						"FractionalPart.NumberOfDigits = %d, expected %d",
						part.NumberOfDigits,
						wanted.NumberOfDigits,
					)
				}

				if part.FractionalValue != wanted.FractionalValue {
					t.Errorf(
						"FractionalPart.FractionalValue = %d, expected %d",
						part.FractionalValue,
						wanted.FractionalValue,
					)
				}
			}
		})
	}
}

// checkOptInt64 is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func checkOptInt64(t *testing.T, name string, got, want *int64) {
	t.Helper()

	if (got == nil) != (want == nil) {
		t.Errorf("%s presence = %v, expected %v", name, got != nil, want != nil)
		return
	}

	if got != nil && *got != *want {
		t.Errorf("%s = %d, expected %d", name, *got, *want)
	}
}

// HOURS_AND_DIFF_AND_FRACTION_ENCODING_TC represents a single
// HoursAndDiffAndFractionEncoding test case from
// hours_and_diff_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/hours_and_diff_and_fraction_encoding.py.
type HOURS_AND_DIFF_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		LocalHours  int64  `json:"local_hours"`
		Fraction    int64  `json:"fraction"`
		Sign        string `json:"sign"`
		DiffHours   int64  `json:"diff_hours"`
		DiffMinutes *int64 `json:"diff_minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadHoursAndDiffAndFractionEncodingTestCases reads the vectors for
// HoursAndDiffAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadHoursAndDiffAndFractionEncodingTestCases(
	t *testing.T,
) []HOURS_AND_DIFF_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "hours_and_diff_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []HOURS_AND_DIFF_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalHoursAndDiffAndFractionEncoding checks that HoursAndDiffAndFractionEncoding encodes
// to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalHoursAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"LOCAL_%d_FRACTION_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.LocalHours,
			tc.Input.Fraction,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.HoursAndDiffAndFractionEncoding{
				LocalHours: tc.Input.LocalHours,
				Fraction:   tc.Input.Fraction,
				TimeDifference: buildTimeDifference(
					tc.Input.Sign,
					tc.Input.DiffHours,
					tc.Input.DiffMinutes,
				),
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

// TestUnmarshalHoursAndDiffAndFractionEncoding checks that HoursAndDiffAndFractionEncoding decodes
// from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalHoursAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"LOCAL_%d_FRACTION_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.LocalHours,
			tc.Input.Fraction,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.HoursAndDiffAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalHours != tc.Input.LocalHours {
				t.Errorf(
					"LocalHours = %d, expected %d",
					value.LocalHours,
					tc.Input.LocalHours,
				)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}

			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"TimeDifference.Sign = %d, expected %d",
					value.TimeDifference.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf(
					"TimeDifference.Hours = %d, expected %d",
					value.TimeDifference.Hours,
					tc.Input.DiffHours,
				)
			}

			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf(
					"TimeDifference.Minutes presence = %v, expected %v",
					value.TimeDifference.Minutes != nil,
					tc.Input.DiffMinutes != nil,
				)
			} else if value.TimeDifference.Minutes != nil &&
				*value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf(
					"TimeDifference.Minutes = %d, expected %d",
					*value.TimeDifference.Minutes,
					*tc.Input.DiffMinutes,
				)
			}
		})
	}
}

// HOURS_AND_DIFF_ENCODING_TC represents a single HoursAndDiffEncoding test
// case from hours_and_diff_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/hours_and_diff_encoding.py.
type HOURS_AND_DIFF_ENCODING_TC struct {
	Input struct {
		LocalHours  int64  `json:"local_hours"`
		Sign        string `json:"sign"`
		DiffHours   int64  `json:"diff_hours"`
		DiffMinutes *int64 `json:"diff_minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadHoursAndDiffEncodingTestCases reads the vectors for HoursAndDiffEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadHoursAndDiffEncodingTestCases(t *testing.T) []HOURS_AND_DIFF_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "hours_and_diff_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []HOURS_AND_DIFF_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// buildTimeDifference is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func buildTimeDifference(sign string, hours int64, minutes *int64) *builtin.TimeDifference {
	return &builtin.TimeDifference{
		Sign:    timeDifferenceSignFor(sign),
		Hours:   hours,
		Minutes: minutes,
	}
}

// TestMarshalHoursAndDiffEncoding checks that HoursAndDiffEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalHoursAndDiffEncoding(t *testing.T) {
	tests := loadHoursAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"LOCAL_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.LocalHours,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.HoursAndDiffEncoding{
				LocalHours: tc.Input.LocalHours,
				TimeDifference: buildTimeDifference(
					tc.Input.Sign,
					tc.Input.DiffHours,
					tc.Input.DiffMinutes,
				),
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

// TestUnmarshalHoursAndDiffEncoding checks that HoursAndDiffEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalHoursAndDiffEncoding(t *testing.T) {
	tests := loadHoursAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"LOCAL_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.LocalHours,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.HoursAndDiffEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalHours != tc.Input.LocalHours {
				t.Errorf(
					"LocalHours = %d, expected %d",
					value.LocalHours,
					tc.Input.LocalHours,
				)
			}

			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"TimeDifference.Sign = %d, expected %d",
					value.TimeDifference.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf(
					"TimeDifference.Hours = %d, expected %d",
					value.TimeDifference.Hours,
					tc.Input.DiffHours,
				)
			}

			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf(
					"TimeDifference.Minutes presence = %v, expected %v",
					value.TimeDifference.Minutes != nil,
					tc.Input.DiffMinutes != nil,
				)
			} else if value.TimeDifference.Minutes != nil &&
				*value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf(
					"TimeDifference.Minutes = %d, expected %d",
					*value.TimeDifference.Minutes,
					*tc.Input.DiffMinutes,
				)
			}
		})
	}
}

// HOURS_AND_FRACTION_ENCODING_TC represents a single
// HoursAndFractionEncoding test case from hours_and_fraction_encoding.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see builtin/testing/hours_and_fraction_encoding.py.
type HOURS_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadHoursAndFractionEncodingTestCases reads the vectors for HoursAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadHoursAndFractionEncodingTestCases(t *testing.T) []HOURS_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "hours_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []HOURS_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalHoursAndFractionEncoding checks that HoursAndFractionEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalHoursAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_FRACTION_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.HoursAndFractionEncoding{
				Hours:    tc.Input.Hours,
				Fraction: tc.Input.Fraction,
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

// TestUnmarshalHoursAndFractionEncoding checks that HoursAndFractionEncoding decodes from its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalHoursAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_FRACTION_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.HoursAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}
		})
	}
}

// HOURS_ENCODING_TC represents a single HoursEncoding test case from
// hours_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/hours_encoding.py.
type HOURS_ENCODING_TC struct {
	Input struct {
		Hours int64 `json:"hours"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadHoursEncodingTestCases reads the vectors for HoursEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadHoursEncodingTestCases(t *testing.T) []HOURS_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "hours_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []HOURS_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalHoursEncoding checks that HoursEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalHoursEncoding(t *testing.T) {
	tests := loadHoursEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := builtin.HoursEncoding(tc.Input.Hours)

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

// TestUnmarshalHoursEncoding checks that HoursEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalHoursEncoding(t *testing.T) {
	tests := loadHoursEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.HoursEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value) != tc.Input.Hours {
				t.Errorf("value = %d, expected %d", value, tc.Input.Hours)
			}
		})
	}
}

// HOURS_UTC_AND_FRACTION_ENCODING_TC represents a single
// HoursUtcAndFractionEncoding test case from
// hours_utc_and_fraction_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/hours_utc_and_fraction_encoding.py.
type HOURS_UTC_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadHoursUtcAndFractionEncodingTestCases reads the vectors for HoursUtcAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadHoursUtcAndFractionEncodingTestCases(t *testing.T) []HOURS_UTC_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "hours_utc_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []HOURS_UTC_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalHoursUtcAndFractionEncoding checks that HoursUtcAndFractionEncoding encodes to its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalHoursUtcAndFractionEncoding(t *testing.T) {
	tests := loadHoursUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_FRACTION_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.HoursUtcAndFractionEncoding{
				Hours:    tc.Input.Hours,
				Fraction: tc.Input.Fraction,
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

// TestUnmarshalHoursUtcAndFractionEncoding checks that HoursUtcAndFractionEncoding decodes from
// its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalHoursUtcAndFractionEncoding(t *testing.T) {
	tests := loadHoursUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_FRACTION_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.HoursUtcAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}
		})
	}
}

// HOURS_UTC_ENCODING_TC represents a single HoursUtcEncoding test case
// from hours_utc_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/hours_utc_encoding.py.
type HOURS_UTC_ENCODING_TC struct {
	Input struct {
		Hours int64 `json:"hours"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadHoursUtcEncodingTestCases reads the vectors for HoursUtcEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadHoursUtcEncodingTestCases(t *testing.T) []HOURS_UTC_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "hours_utc_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []HOURS_UTC_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalHoursUtcEncoding checks that HoursUtcEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalHoursUtcEncoding(t *testing.T) {
	tests := loadHoursUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := builtin.HoursUtcEncoding(tc.Input.Hours)

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

// TestUnmarshalHoursUtcEncoding checks that HoursUtcEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalHoursUtcEncoding(t *testing.T) {
	tests := loadHoursUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.HoursUtcEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if int64(value) != tc.Input.Hours {
				t.Errorf("value = %d, expected %d", value, tc.Input.Hours)
			}
		})
	}
}

// MINUTES_AND_DIFF_AND_FRACTION_ENCODING_TC represents a single
// MinutesAndDiffAndFractionEncoding test case from
// minutes_and_diff_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/minutes_and_diff_and_fraction_encoding.py.
type MINUTES_AND_DIFF_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours       int64  `json:"hours"`
		Minutes     int64  `json:"minutes"`
		Fraction    int64  `json:"fraction"`
		Sign        string `json:"sign"`
		DiffHours   int64  `json:"diff_hours"`
		DiffMinutes *int64 `json:"diff_minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadMinutesAndDiffAndFractionEncodingTestCases reads the vectors for
// MinutesAndDiffAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadMinutesAndDiffAndFractionEncodingTestCases(
	t *testing.T,
) []MINUTES_AND_DIFF_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "minutes_and_diff_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []MINUTES_AND_DIFF_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalMinutesAndDiffAndFractionEncoding checks that MinutesAndDiffAndFractionEncoding
// encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalMinutesAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HM_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Fraction,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.MinutesAndDiffAndFractionEncoding{
				LocalTime: &builtin.MinutesAndDiffAndFractionEncoding_LocalTime{
					Hours:    tc.Input.Hours,
					Minutes:  tc.Input.Minutes,
					Fraction: tc.Input.Fraction,
				},
				TimeDifference: buildTimeDifference(
					tc.Input.Sign,
					tc.Input.DiffHours,
					tc.Input.DiffMinutes,
				),
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

// TestUnmarshalMinutesAndDiffAndFractionEncoding checks that MinutesAndDiffAndFractionEncoding
// decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalMinutesAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HM_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Fraction,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.MinutesAndDiffAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf(
					"LocalTime.Hours = %d, expected %d",
					value.LocalTime.Hours,
					tc.Input.Hours,
				)
			}

			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf(
					"LocalTime.Minutes = %d, expected %d",
					value.LocalTime.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.LocalTime.Fraction != tc.Input.Fraction {
				t.Errorf(
					"LocalTime.Fraction = %d, expected %d",
					value.LocalTime.Fraction,
					tc.Input.Fraction,
				)
			}

			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"TimeDifference.Sign = %d, expected %d",
					value.TimeDifference.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf(
					"TimeDifference.Hours = %d, expected %d",
					value.TimeDifference.Hours,
					tc.Input.DiffHours,
				)
			}

			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf(
					"TimeDifference.Minutes presence = %v, expected %v",
					value.TimeDifference.Minutes != nil,
					tc.Input.DiffMinutes != nil,
				)
			} else if value.TimeDifference.Minutes != nil &&
				*value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf(
					"TimeDifference.Minutes = %d, expected %d",
					*value.TimeDifference.Minutes,
					*tc.Input.DiffMinutes,
				)
			}
		})
	}
}

// MINUTES_AND_DIFF_ENCODING_TC represents a single MinutesAndDiffEncoding
// test case from minutes_and_diff_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/minutes_and_diff_encoding.py.
type MINUTES_AND_DIFF_ENCODING_TC struct {
	Input struct {
		Hours       int64  `json:"hours"`
		Minutes     int64  `json:"minutes"`
		Sign        string `json:"sign"`
		DiffHours   int64  `json:"diff_hours"`
		DiffMinutes *int64 `json:"diff_minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadMinutesAndDiffEncodingTestCases reads the vectors for MinutesAndDiffEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadMinutesAndDiffEncodingTestCases(t *testing.T) []MINUTES_AND_DIFF_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "minutes_and_diff_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []MINUTES_AND_DIFF_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalMinutesAndDiffEncoding checks that MinutesAndDiffEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalMinutesAndDiffEncoding(t *testing.T) {
	tests := loadMinutesAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HM_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.MinutesAndDiffEncoding{
				LocalTime: &builtin.MinutesAndDiffEncoding_LocalTime{
					Hours:   tc.Input.Hours,
					Minutes: tc.Input.Minutes,
				},
				TimeDifference: buildTimeDifference(
					tc.Input.Sign,
					tc.Input.DiffHours,
					tc.Input.DiffMinutes,
				),
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

// TestUnmarshalMinutesAndDiffEncoding checks that MinutesAndDiffEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalMinutesAndDiffEncoding(t *testing.T) {
	tests := loadMinutesAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HM_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.MinutesAndDiffEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf(
					"LocalTime.Hours = %d, expected %d",
					value.LocalTime.Hours,
					tc.Input.Hours,
				)
			}

			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf(
					"LocalTime.Minutes = %d, expected %d",
					value.LocalTime.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"TimeDifference.Sign = %d, expected %d",
					value.TimeDifference.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf(
					"TimeDifference.Hours = %d, expected %d",
					value.TimeDifference.Hours,
					tc.Input.DiffHours,
				)
			}

			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf(
					"TimeDifference.Minutes presence = %v, expected %v",
					value.TimeDifference.Minutes != nil,
					tc.Input.DiffMinutes != nil,
				)
			} else if value.TimeDifference.Minutes != nil &&
				*value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf(
					"TimeDifference.Minutes = %d, expected %d",
					*value.TimeDifference.Minutes,
					*tc.Input.DiffMinutes,
				)
			}
		})
	}
}

// MINUTES_AND_FRACTION_ENCODING_TC represents a single
// MinutesAndFractionEncoding test case from minutes_and_fraction_encoding.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see builtin/testing/minutes_and_fraction_encoding.py.
type MINUTES_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Minutes  int64 `json:"minutes"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadMinutesAndFractionEncodingTestCases reads the vectors for MinutesAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadMinutesAndFractionEncodingTestCases(t *testing.T) []MINUTES_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "minutes_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []MINUTES_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalMinutesAndFractionEncoding checks that MinutesAndFractionEncoding encodes to its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalMinutesAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.MinutesAndFractionEncoding{
				Hours:    tc.Input.Hours,
				Minutes:  tc.Input.Minutes,
				Fraction: tc.Input.Fraction,
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

// TestUnmarshalMinutesAndFractionEncoding checks that MinutesAndFractionEncoding decodes from its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalMinutesAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.MinutesAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}
		})
	}
}

// MINUTES_ENCODING_TC represents a single MinutesEncoding test case from
// minutes_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/minutes_encoding.py.
type MINUTES_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadMinutesEncodingTestCases reads the vectors for MinutesEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadMinutesEncodingTestCases(t *testing.T) []MINUTES_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "minutes_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []MINUTES_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalMinutesEncoding checks that MinutesEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalMinutesEncoding(t *testing.T) {
	tests := loadMinutesEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_MINUTES_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.MinutesEncoding{
				Hours:   tc.Input.Hours,
				Minutes: tc.Input.Minutes,
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

// TestUnmarshalMinutesEncoding checks that MinutesEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalMinutesEncoding(t *testing.T) {
	tests := loadMinutesEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_MINUTES_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.MinutesEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}
		})
	}
}

// MINUTES_UTC_AND_FRACTION_ENCODING_TC represents a single
// MinutesUtcAndFractionEncoding test case from
// minutes_utc_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/minutes_utc_and_fraction_encoding.py.
type MINUTES_UTC_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Minutes  int64 `json:"minutes"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadMinutesUtcAndFractionEncodingTestCases reads the vectors for MinutesUtcAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadMinutesUtcAndFractionEncodingTestCases(
	t *testing.T,
) []MINUTES_UTC_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "minutes_utc_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []MINUTES_UTC_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalMinutesUtcAndFractionEncoding checks that MinutesUtcAndFractionEncoding encodes to
// its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalMinutesUtcAndFractionEncoding(t *testing.T) {
	tests := loadMinutesUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.MinutesUtcAndFractionEncoding{
				Hours:    tc.Input.Hours,
				Minutes:  tc.Input.Minutes,
				Fraction: tc.Input.Fraction,
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

// TestUnmarshalMinutesUtcAndFractionEncoding checks that MinutesUtcAndFractionEncoding decodes
// from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalMinutesUtcAndFractionEncoding(t *testing.T) {
	tests := loadMinutesUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.MinutesUtcAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}
		})
	}
}

// MINUTES_UTC_ENCODING_TC represents a single MinutesUtcEncoding test case
// from minutes_utc_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/minutes_utc_encoding.py.
type MINUTES_UTC_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadMinutesUtcEncodingTestCases reads the vectors for MinutesUtcEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadMinutesUtcEncodingTestCases(t *testing.T) []MINUTES_UTC_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "minutes_utc_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []MINUTES_UTC_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalMinutesUtcEncoding checks that MinutesUtcEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalMinutesUtcEncoding(t *testing.T) {
	tests := loadMinutesUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_MINUTES_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.MinutesUtcEncoding{
				Hours:   tc.Input.Hours,
				Minutes: tc.Input.Minutes,
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

// TestUnmarshalMinutesUtcEncoding checks that MinutesUtcEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalMinutesUtcEncoding(t *testing.T) {
	tests := loadMinutesUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HOURS_%d_MINUTES_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.MinutesUtcEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}
		})
	}
}

// TIME_DIFFERENCE_TC represents a single TimeDifference test case from
// time_difference.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/time_difference.py.
type TIME_DIFFERENCE_TC struct {
	Input struct {
		Sign    string `json:"sign"`
		Hours   int64  `json:"hours"`
		Minutes *int64 `json:"minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeDifferenceTestCases reads the vectors for TimeDifference.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeDifferenceTestCases(t *testing.T) []TIME_DIFFERENCE_TC {
	t.Helper()

	path := filepath.Join("testing", "time_difference.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_DIFFERENCE_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// timeDifferenceSignFor is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func timeDifferenceSignFor(sign string) builtin.TimeDifferenceSign {
	if sign == "negative" {
		return builtin.TIME_DIFFERENCE_SIGN_NEGATIVE
	}

	return builtin.TIME_DIFFERENCE_SIGN_POSITIVE
}

// timeDifferenceMinutesLabel is a helper for the cases below.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func timeDifferenceMinutesLabel(minutes *int64) string {
	if minutes == nil {
		return "NONE"
	}

	return fmt.Sprintf("%d", *minutes)
}

// TestMarshalTimeDifference checks that TimeDifference encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeDifference(t *testing.T) {
	tests := loadTimeDifferenceTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"SIGN_%s_HOURS_%d_MINUTES_%s_ALIGNED_%v",
			tc.Input.Sign,
			tc.Input.Hours,
			timeDifferenceMinutesLabel(tc.Input.Minutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeDifference{
				Sign:    timeDifferenceSignFor(tc.Input.Sign),
				Hours:   tc.Input.Hours,
				Minutes: tc.Input.Minutes,
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

// TestUnmarshalTimeDifference checks that TimeDifference decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeDifference(t *testing.T) {
	tests := loadTimeDifferenceTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"SIGN_%s_HOURS_%d_MINUTES_%s_ALIGNED_%v",
			tc.Input.Sign,
			tc.Input.Hours,
			timeDifferenceMinutesLabel(tc.Input.Minutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeDifference
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"Sign = %d, expected %d",
					value.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if (value.Minutes == nil) != (tc.Input.Minutes == nil) {
				t.Errorf(
					"Minutes presence = %v, expected %v",
					value.Minutes != nil,
					tc.Input.Minutes != nil,
				)
			} else if value.Minutes != nil && *value.Minutes != *tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					*value.Minutes,
					*tc.Input.Minutes,
				)
			}
		})
	}
}

// TIME_OF_DAY_AND_DIFF_AND_FRACTION_ENCODING_TC represents a single
// TimeOfDayAndDiffAndFractionEncoding test case from
// time_of_day_and_diff_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/time_of_day_and_diff_and_fraction_encoding.py.
type TIME_OF_DAY_AND_DIFF_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours       int64  `json:"hours"`
		Minutes     int64  `json:"minutes"`
		Seconds     int64  `json:"seconds"`
		Fraction    int64  `json:"fraction"`
		Sign        string `json:"sign"`
		DiffHours   int64  `json:"diff_hours"`
		DiffMinutes *int64 `json:"diff_minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeOfDayAndDiffAndFractionEncodingTestCases reads the vectors for
// TimeOfDayAndDiffAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeOfDayAndDiffAndFractionEncodingTestCases(
	t *testing.T,
) []TIME_OF_DAY_AND_DIFF_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "time_of_day_and_diff_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_OF_DAY_AND_DIFF_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalTimeOfDayAndDiffAndFractionEncoding checks that TimeOfDayAndDiffAndFractionEncoding
// encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeOfDayAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HMS_%d_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Fraction,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeOfDayAndDiffAndFractionEncoding{
				LocalTime: &builtin.TimeOfDayAndDiffAndFractionEncoding_LocalTime{
					Hours:    tc.Input.Hours,
					Minutes:  tc.Input.Minutes,
					Seconds:  tc.Input.Seconds,
					Fraction: tc.Input.Fraction,
				},
				TimeDifference: buildTimeDifference(
					tc.Input.Sign,
					tc.Input.DiffHours,
					tc.Input.DiffMinutes,
				),
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

// TestUnmarshalTimeOfDayAndDiffAndFractionEncoding checks that TimeOfDayAndDiffAndFractionEncoding
// decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeOfDayAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HMS_%d_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Fraction,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeOfDayAndDiffAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf(
					"LocalTime.Hours = %d, expected %d",
					value.LocalTime.Hours,
					tc.Input.Hours,
				)
			}

			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf(
					"LocalTime.Minutes = %d, expected %d",
					value.LocalTime.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.LocalTime.Seconds != tc.Input.Seconds {
				t.Errorf(
					"LocalTime.Seconds = %d, expected %d",
					value.LocalTime.Seconds,
					tc.Input.Seconds,
				)
			}

			if value.LocalTime.Fraction != tc.Input.Fraction {
				t.Errorf(
					"LocalTime.Fraction = %d, expected %d",
					value.LocalTime.Fraction,
					tc.Input.Fraction,
				)
			}

			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"TimeDifference.Sign = %d, expected %d",
					value.TimeDifference.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf(
					"TimeDifference.Hours = %d, expected %d",
					value.TimeDifference.Hours,
					tc.Input.DiffHours,
				)
			}

			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf(
					"TimeDifference.Minutes presence = %v, expected %v",
					value.TimeDifference.Minutes != nil,
					tc.Input.DiffMinutes != nil,
				)
			} else if value.TimeDifference.Minutes != nil &&
				*value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf(
					"TimeDifference.Minutes = %d, expected %d",
					*value.TimeDifference.Minutes,
					*tc.Input.DiffMinutes,
				)
			}
		})
	}
}

// TIME_OF_DAY_AND_DIFF_ENCODING_TC represents a single
// TimeOfDayAndDiffEncoding test case from time_of_day_and_diff_encoding.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see builtin/testing/time_of_day_and_diff_encoding.py.
type TIME_OF_DAY_AND_DIFF_ENCODING_TC struct {
	Input struct {
		Hours       int64  `json:"hours"`
		Minutes     int64  `json:"minutes"`
		Seconds     int64  `json:"seconds"`
		Sign        string `json:"sign"`
		DiffHours   int64  `json:"diff_hours"`
		DiffMinutes *int64 `json:"diff_minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeOfDayAndDiffEncodingTestCases reads the vectors for TimeOfDayAndDiffEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeOfDayAndDiffEncodingTestCases(t *testing.T) []TIME_OF_DAY_AND_DIFF_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "time_of_day_and_diff_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_OF_DAY_AND_DIFF_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalTimeOfDayAndDiffEncoding checks that TimeOfDayAndDiffEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeOfDayAndDiffEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HMS_%d_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeOfDayAndDiffEncoding{
				LocalTime: &builtin.TimeOfDayAndDiffEncoding_LocalTime{
					Hours:   tc.Input.Hours,
					Minutes: tc.Input.Minutes,
					Seconds: tc.Input.Seconds,
				},
				TimeDifference: buildTimeDifference(
					tc.Input.Sign,
					tc.Input.DiffHours,
					tc.Input.DiffMinutes,
				),
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

// TestUnmarshalTimeOfDayAndDiffEncoding checks that TimeOfDayAndDiffEncoding decodes from its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeOfDayAndDiffEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"HMS_%d_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Sign,
			tc.Input.DiffHours,
			timeDifferenceMinutesLabel(tc.Input.DiffMinutes),
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeOfDayAndDiffEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf(
					"LocalTime.Hours = %d, expected %d",
					value.LocalTime.Hours,
					tc.Input.Hours,
				)
			}

			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf(
					"LocalTime.Minutes = %d, expected %d",
					value.LocalTime.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.LocalTime.Seconds != tc.Input.Seconds {
				t.Errorf(
					"LocalTime.Seconds = %d, expected %d",
					value.LocalTime.Seconds,
					tc.Input.Seconds,
				)
			}

			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf(
					"TimeDifference.Sign = %d, expected %d",
					value.TimeDifference.Sign,
					timeDifferenceSignFor(tc.Input.Sign),
				)
			}

			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf(
					"TimeDifference.Hours = %d, expected %d",
					value.TimeDifference.Hours,
					tc.Input.DiffHours,
				)
			}

			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf(
					"TimeDifference.Minutes presence = %v, expected %v",
					value.TimeDifference.Minutes != nil,
					tc.Input.DiffMinutes != nil,
				)
			} else if value.TimeDifference.Minutes != nil &&
				*value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf(
					"TimeDifference.Minutes = %d, expected %d",
					*value.TimeDifference.Minutes,
					*tc.Input.DiffMinutes,
				)
			}
		})
	}
}

// TIME_OF_DAY_AND_FRACTION_ENCODING_TC represents a single
// TimeOfDayAndFractionEncoding test case from
// time_of_day_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/time_of_day_and_fraction_encoding.py.
type TIME_OF_DAY_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Minutes  int64 `json:"minutes"`
		Seconds  int64 `json:"seconds"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeOfDayAndFractionEncodingTestCases reads the vectors for TimeOfDayAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeOfDayAndFractionEncodingTestCases(
	t *testing.T,
) []TIME_OF_DAY_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "time_of_day_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_OF_DAY_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalTimeOfDayAndFractionEncoding checks that TimeOfDayAndFractionEncoding encodes to its
// vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeOfDayAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeOfDayAndFractionEncoding{
				Hours:    tc.Input.Hours,
				Minutes:  tc.Input.Minutes,
				Seconds:  tc.Input.Seconds,
				Fraction: tc.Input.Fraction,
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

// TestUnmarshalTimeOfDayAndFractionEncoding checks that TimeOfDayAndFractionEncoding decodes from
// its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeOfDayAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeOfDayAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.Seconds != tc.Input.Seconds {
				t.Errorf(
					"Seconds = %d, expected %d",
					value.Seconds,
					tc.Input.Seconds,
				)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}
		})
	}
}

// TIME_OF_DAY_ENCODING_TC represents a single TimeOfDayEncoding test case
// from time_of_day_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/time_of_day_encoding.py.
type TIME_OF_DAY_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
		Seconds int64 `json:"seconds"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeOfDayEncodingTestCases reads the vectors for TimeOfDayEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeOfDayEncodingTestCases(t *testing.T) []TIME_OF_DAY_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "time_of_day_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_OF_DAY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalTimeOfDayEncoding checks that TimeOfDayEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeOfDayEncoding(t *testing.T) {
	tests := loadTimeOfDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeOfDayEncoding{
				Hours:   tc.Input.Hours,
				Minutes: tc.Input.Minutes,
				Seconds: tc.Input.Seconds,
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

// TestUnmarshalTimeOfDayEncoding checks that TimeOfDayEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeOfDayEncoding(t *testing.T) {
	tests := loadTimeOfDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeOfDayEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.Seconds != tc.Input.Seconds {
				t.Errorf(
					"Seconds = %d, expected %d",
					value.Seconds,
					tc.Input.Seconds,
				)
			}
		})
	}
}

// TIME_OF_DAY_UTC_AND_FRACTION_ENCODING_TC represents a single
// TimeOfDayUtcAndFractionEncoding test case from
// time_of_day_utc_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/time_of_day_utc_and_fraction_encoding.py.
type TIME_OF_DAY_UTC_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Minutes  int64 `json:"minutes"`
		Seconds  int64 `json:"seconds"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeOfDayUtcAndFractionEncodingTestCases reads the vectors for
// TimeOfDayUtcAndFractionEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeOfDayUtcAndFractionEncodingTestCases(
	t *testing.T,
) []TIME_OF_DAY_UTC_AND_FRACTION_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "time_of_day_utc_and_fraction_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_OF_DAY_UTC_AND_FRACTION_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalTimeOfDayUtcAndFractionEncoding checks that TimeOfDayUtcAndFractionEncoding encodes
// to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeOfDayUtcAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeOfDayUtcAndFractionEncoding{
				Hours:    tc.Input.Hours,
				Minutes:  tc.Input.Minutes,
				Seconds:  tc.Input.Seconds,
				Fraction: tc.Input.Fraction,
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

// TestUnmarshalTimeOfDayUtcAndFractionEncoding checks that TimeOfDayUtcAndFractionEncoding decodes
// from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeOfDayUtcAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_F_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Input.Fraction,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeOfDayUtcAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.Seconds != tc.Input.Seconds {
				t.Errorf(
					"Seconds = %d, expected %d",
					value.Seconds,
					tc.Input.Seconds,
				)
			}

			if value.Fraction != tc.Input.Fraction {
				t.Errorf(
					"Fraction = %d, expected %d",
					value.Fraction,
					tc.Input.Fraction,
				)
			}
		})
	}
}

// TIME_OF_DAY_UTC_ENCODING_TC represents a single TimeOfDayUtcEncoding
// test case from time_of_day_utc_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/time_of_day_utc_encoding.py.
type TIME_OF_DAY_UTC_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
		Seconds int64 `json:"seconds"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadTimeOfDayUtcEncodingTestCases reads the vectors for TimeOfDayUtcEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadTimeOfDayUtcEncodingTestCases(t *testing.T) []TIME_OF_DAY_UTC_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "time_of_day_utc_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []TIME_OF_DAY_UTC_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalTimeOfDayUtcEncoding checks that TimeOfDayUtcEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalTimeOfDayUtcEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.TimeOfDayUtcEncoding{
				Hours:   tc.Input.Hours,
				Minutes: tc.Input.Minutes,
				Seconds: tc.Input.Seconds,
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

// TestUnmarshalTimeOfDayUtcEncoding checks that TimeOfDayUtcEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalTimeOfDayUtcEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"H_%d_M_%d_S_%d_ALIGNED_%v",
			tc.Input.Hours,
			tc.Input.Minutes,
			tc.Input.Seconds,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.TimeOfDayUtcEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}

			if value.Minutes != tc.Input.Minutes {
				t.Errorf(
					"Minutes = %d, expected %d",
					value.Minutes,
					tc.Input.Minutes,
				)
			}

			if value.Seconds != tc.Input.Seconds {
				t.Errorf(
					"Seconds = %d, expected %d",
					value.Seconds,
					tc.Input.Seconds,
				)
			}
		})
	}
}

// YEAR_DAY_ENCODING_TC represents a single YearDayEncoding test case from
// year_day_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/year_day_encoding.py.
type YEAR_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadYearDayEncodingTestCases reads the vectors for YearDayEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadYearDayEncodingTestCases(t *testing.T) []YEAR_DAY_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "year_day_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []YEAR_DAY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalYearDayEncoding checks that YearDayEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalYearDayEncoding(t *testing.T) {
	tests := loadYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.YearDayEncoding{
				Year: yearEncodingForYear((tc.Input.Year)),
				Day:  tc.Input.Day,
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

// TestUnmarshalYearDayEncoding checks that YearDayEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalYearDayEncoding(t *testing.T) {
	tests := loadYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.YearDayEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year.Year() != tc.Input.Year {
				t.Errorf(
					"Year.Year() = %d, expected %d",
					value.Year.Year(),
					tc.Input.Year,
				)
			}

			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}

// YEAR_WEEK_DAY_ENCODING_TC represents a single YearWeekDayEncoding test
// case from year_week_day_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/year_week_day_encoding.py.
type YEAR_WEEK_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadYearWeekDayEncodingTestCases reads the vectors for YearWeekDayEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadYearWeekDayEncodingTestCases(t *testing.T) []YEAR_WEEK_DAY_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "year_week_day_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []YEAR_WEEK_DAY_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalYearWeekDayEncoding checks that YearWeekDayEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalYearWeekDayEncoding(t *testing.T) {
	tests := loadYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.YearWeekDayEncoding{
				Year: yearEncodingForYear((tc.Input.Year)),
				Week: tc.Input.Week,
				Day:  tc.Input.Day,
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

// TestUnmarshalYearWeekDayEncoding checks that YearWeekDayEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalYearWeekDayEncoding(t *testing.T) {
	tests := loadYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Input.Day,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.YearWeekDayEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year.Year() != tc.Input.Year {
				t.Errorf(
					"Year.Year() = %d, expected %d",
					value.Year.Year(),
					tc.Input.Year,
				)
			}

			if value.Week != tc.Input.Week {
				t.Errorf("Week = %d, expected %d", value.Week, tc.Input.Week)
			}

			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}

// YEAR_WEEK_ENCODING_TC represents a single YearWeekEncoding test case from
// year_week_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// builtin/testing/year_week_encoding.py.
type YEAR_WEEK_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

// loadYearWeekEncodingTestCases reads the vectors for YearWeekEncoding.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func loadYearWeekEncodingTestCases(t *testing.T) []YEAR_WEEK_ENCODING_TC {
	t.Helper()

	path := filepath.Join("testing", "year_week_encoding.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	var tests []YEAR_WEEK_ENCODING_TC
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	return tests
}

// TestMarshalYearWeekEncoding checks that YearWeekEncoding encodes to its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestMarshalYearWeekEncoding(t *testing.T) {
	tests := loadYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			value := builtin.YearWeekEncoding{
				Year: yearEncodingForYear((tc.Input.Year)),
				Week: tc.Input.Week,
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

// TestUnmarshalYearWeekEncoding checks that YearWeekEncoding decodes from its vectors.
//
// Revisions:
//   - 2026-07-06 09:55: initial creation
func TestUnmarshalYearWeekEncoding(t *testing.T) {
	tests := loadYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf(
			"YEAR_%d_WEEK_%d_ALIGNED_%v",
			tc.Input.Year,
			tc.Input.Week,
			tc.Aligned,
		)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value builtin.YearWeekEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}

			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Year.Year() != tc.Input.Year {
				t.Errorf(
					"Year.Year() = %d, expected %d",
					value.Year.Year(),
					tc.Input.Year,
				)
			}

			if value.Week != tc.Input.Week {
				t.Errorf("Week = %d, expected %d", value.Week, tc.Input.Week)
			}
		})
	}
}
