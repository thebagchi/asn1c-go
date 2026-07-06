package builtin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ANY_CENTURY_ENCODING_TC represents a single AnyCenturyEncoding test case
// from any_century_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/any_century_encoding.py.
type ANY_CENTURY_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalAnyCenturyEncoding(t *testing.T) {
	tests := loadAnyCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := AnyCenturyEncoding(tc.Input.Value)

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

func TestUnmarshalAnyCenturyEncoding(t *testing.T) {
	tests := loadAnyCenturyEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value AnyCenturyEncoding
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
// lib/builtin/testing/any_year_encoding.py.
type ANY_YEAR_ENCODING_TC struct {
	Input struct {
		Value int64 `json:"value"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalAnyYearEncoding(t *testing.T) {
	tests := loadAnyYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := AnyYearEncoding(tc.Input.Value)

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

func TestUnmarshalAnyYearEncoding(t *testing.T) {
	tests := loadAnyYearEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("VALUE_%d_ALIGNED_%v", tc.Input.Value, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value AnyYearEncoding
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
)

// ANY_DATE_ENCODING_TC represents a single AnyDateEncoding test case from
// any_date_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/any_date_encoding.py.
type ANY_DATE_ENCODING_TC struct {
	Input struct {
		Year  int64 `json:"year"`
		Month int64 `json:"month"`
		Day   int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalAnyDateEncoding(t *testing.T) {
	tests := loadAnyDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Month, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := AnyDateEncoding{
				Year:  AnyYearEncoding(tc.Input.Year),
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

func TestUnmarshalAnyDateEncoding(t *testing.T) {
	tests := loadAnyDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Month, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value AnyDateEncoding
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
)

// ANY_YEAR_DAY_ENCODING_TC represents a single AnyYearDayEncoding test case
// from any_year_day_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/any_year_day_encoding.py.
type ANY_YEAR_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalAnyYearDayEncoding(t *testing.T) {
	tests := loadAnyYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := AnyYearDayEncoding{
				Year: AnyYearEncoding(tc.Input.Year),
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

func TestUnmarshalAnyYearDayEncoding(t *testing.T) {
	tests := loadAnyYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value AnyYearDayEncoding
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
)

// ANY_YEAR_WEEK_DAY_ENCODING_TC represents a single AnyYearWeekDayEncoding
// test case from any_year_week_day_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/any_year_week_day_encoding.py.
type ANY_YEAR_WEEK_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalAnyYearWeekDayEncoding(t *testing.T) {
	tests := loadAnyYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := AnyYearWeekDayEncoding{
				Year: AnyYearEncoding(tc.Input.Year),
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

func TestUnmarshalAnyYearWeekDayEncoding(t *testing.T) {
	tests := loadAnyYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value AnyYearWeekDayEncoding
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
)

// ANY_YEAR_WEEK_ENCODING_TC represents a single AnyYearWeekEncoding test
// case from any_year_week_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/any_year_week_encoding.py.
type ANY_YEAR_WEEK_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalAnyYearWeekEncoding(t *testing.T) {
	tests := loadAnyYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := AnyYearWeekEncoding{
				Year: AnyYearEncoding(tc.Input.Year),
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

func TestUnmarshalAnyYearWeekEncoding(t *testing.T) {
	tests := loadAnyYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value AnyYearWeekEncoding
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
)

// DATE_ENCODING_TC represents a single DateEncoding test case from
// date_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/date_encoding.py.
type DATE_ENCODING_TC struct {
	Input struct {
		Year  int64 `json:"year"`
		Month int64 `json:"month"`
		Day   int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalDateEncoding(t *testing.T) {
	tests := loadDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Month, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := DateEncoding{
				Year:  NewYearEncoding(yearEncodingChoiceForYear(tc.Input.Year)),
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

func TestUnmarshalDateEncoding(t *testing.T) {
	tests := loadDateEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_MONTH_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Month, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value DateEncoding
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
			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}
)

// DURATION_EQUIVALENT_TC represents a single DurationEquivalent test case
// from duration_equivalent.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/duration_equivalent.py.
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

func durationEquivalentFromTC(tc DURATION_EQUIVALENT_TC) DurationEquivalent {
	value := DurationEquivalent{
		Years:   tc.Input.Years,
		Months:  tc.Input.Months,
		Weeks:   tc.Input.Weeks,
		Days:    tc.Input.Days,
		Hours:   tc.Input.Hours,
		Minutes: tc.Input.Minutes,
		Seconds: tc.Input.Seconds,
	}
	if tc.Input.FractionalPart != nil {
		value.FractionalPart = &DurationEquivalent_FractionalPart{
			NumberOfDigits:  tc.Input.FractionalPart.NumberOfDigits,
			FractionalValue: tc.Input.FractionalPart.FractionalValue,
		}
	}
	return value
}

func TestMarshalDurationEquivalent(t *testing.T) {
	tests := loadDurationEquivalentTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v", intLabel(tc.Input.Years), intLabel(tc.Input.Months), intLabel(tc.Input.Weeks), intLabel(tc.Input.Days), intLabel(tc.Input.Hours), intLabel(tc.Input.Minutes), intLabel(tc.Input.Seconds), tc.Aligned)
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

func TestUnmarshalDurationEquivalent(t *testing.T) {
	tests := loadDurationEquivalentTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v", intLabel(tc.Input.Years), intLabel(tc.Input.Months), intLabel(tc.Input.Weeks), intLabel(tc.Input.Days), intLabel(tc.Input.Hours), intLabel(tc.Input.Minutes), intLabel(tc.Input.Seconds), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value DurationEquivalent
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
				t.Errorf("FractionalPart presence = %v, expected %v", value.FractionalPart != nil, expected.FractionalPart != nil)
			} else if value.FractionalPart != nil {
				if value.FractionalPart.NumberOfDigits != expected.FractionalPart.NumberOfDigits {
					t.Errorf("FractionalPart.NumberOfDigits = %d, expected %d", value.FractionalPart.NumberOfDigits, expected.FractionalPart.NumberOfDigits)
				}
				if value.FractionalPart.FractionalValue != expected.FractionalPart.FractionalValue {
					t.Errorf("FractionalPart.FractionalValue = %d, expected %d", value.FractionalPart.FractionalValue, expected.FractionalPart.FractionalValue)
				}
			}
		})
	}
}
)

// DURATION_INTERVAL_ENCODING_TC represents a single DurationIntervalEncoding
// test case from duration_interval_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/duration_interval_encoding.py.
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

func intLabel(v *int64) string {
	if v == nil {
		return "NONE"
	}
	return fmt.Sprintf("%d", *v)
}

func durationIntervalEncodingFromTC(tc DURATION_INTERVAL_ENCODING_TC) DurationIntervalEncoding {
	value := DurationIntervalEncoding{
		Years:   tc.Input.Years,
		Months:  tc.Input.Months,
		Weeks:   tc.Input.Weeks,
		Days:    tc.Input.Days,
		Hours:   tc.Input.Hours,
		Minutes: tc.Input.Minutes,
		Seconds: tc.Input.Seconds,
	}
	if tc.Input.FractionalPart != nil {
		value.FractionalPart = &DurationIntervalEncoding_FractionalPart{
			NumberOfDigits:  tc.Input.FractionalPart.NumberOfDigits,
			FractionalValue: tc.Input.FractionalPart.FractionalValue,
		}
	}
	return value
}

func TestMarshalDurationIntervalEncoding(t *testing.T) {
	tests := loadDurationIntervalEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v", intLabel(tc.Input.Years), intLabel(tc.Input.Months), intLabel(tc.Input.Weeks), intLabel(tc.Input.Days), intLabel(tc.Input.Hours), intLabel(tc.Input.Minutes), intLabel(tc.Input.Seconds), tc.Aligned)
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

func TestUnmarshalDurationIntervalEncoding(t *testing.T) {
	tests := loadDurationIntervalEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("Y_%s_MO_%s_W_%s_D_%s_H_%s_MI_%s_S_%s_ALIGNED_%v", intLabel(tc.Input.Years), intLabel(tc.Input.Months), intLabel(tc.Input.Weeks), intLabel(tc.Input.Days), intLabel(tc.Input.Hours), intLabel(tc.Input.Minutes), intLabel(tc.Input.Seconds), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value DurationIntervalEncoding
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
				t.Errorf("FractionalPart presence = %v, expected %v", value.FractionalPart != nil, expected.FractionalPart != nil)
			} else if value.FractionalPart != nil {
				if value.FractionalPart.NumberOfDigits != expected.FractionalPart.NumberOfDigits {
					t.Errorf("FractionalPart.NumberOfDigits = %d, expected %d", value.FractionalPart.NumberOfDigits, expected.FractionalPart.NumberOfDigits)
				}
				if value.FractionalPart.FractionalValue != expected.FractionalPart.FractionalValue {
					t.Errorf("FractionalPart.FractionalValue = %d, expected %d", value.FractionalPart.FractionalValue, expected.FractionalPart.FractionalValue)
				}
			}
		})
	}
}

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
)

// HOURS_AND_DIFF_AND_FRACTION_ENCODING_TC represents a single
// HoursAndDiffAndFractionEncoding test case from
// hours_and_diff_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/hours_and_diff_and_fraction_encoding.py.
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

func loadHoursAndDiffAndFractionEncodingTestCases(t *testing.T) []HOURS_AND_DIFF_AND_FRACTION_ENCODING_TC {
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

func TestMarshalHoursAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("LOCAL_%d_FRACTION_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.LocalHours, tc.Input.Fraction, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := HoursAndDiffAndFractionEncoding{
				LocalHours:     tc.Input.LocalHours,
				Fraction:       tc.Input.Fraction,
				TimeDifference: buildTimeDifference(tc.Input.Sign, tc.Input.DiffHours, tc.Input.DiffMinutes),
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

func TestUnmarshalHoursAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("LOCAL_%d_FRACTION_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.LocalHours, tc.Input.Fraction, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value HoursAndDiffAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalHours != tc.Input.LocalHours {
				t.Errorf("LocalHours = %d, expected %d", value.LocalHours, tc.Input.LocalHours)
			}
			if value.Fraction != tc.Input.Fraction {
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("TimeDifference.Sign = %d, expected %d", value.TimeDifference.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf("TimeDifference.Hours = %d, expected %d", value.TimeDifference.Hours, tc.Input.DiffHours)
			}
			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf("TimeDifference.Minutes presence = %v, expected %v", value.TimeDifference.Minutes != nil, tc.Input.DiffMinutes != nil)
			} else if value.TimeDifference.Minutes != nil && *value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf("TimeDifference.Minutes = %d, expected %d", *value.TimeDifference.Minutes, *tc.Input.DiffMinutes)
			}
		})
	}
}
)

// HOURS_AND_DIFF_ENCODING_TC represents a single HoursAndDiffEncoding test
// case from hours_and_diff_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/hours_and_diff_encoding.py.
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

func buildTimeDifference(sign string, hours int64, minutes *int64) *TimeDifference {
	return &TimeDifference{
		Sign:    timeDifferenceSignFor(sign),
		Hours:   hours,
		Minutes: minutes,
	}
}

func TestMarshalHoursAndDiffEncoding(t *testing.T) {
	tests := loadHoursAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("LOCAL_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.LocalHours, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := HoursAndDiffEncoding{
				LocalHours:     tc.Input.LocalHours,
				TimeDifference: buildTimeDifference(tc.Input.Sign, tc.Input.DiffHours, tc.Input.DiffMinutes),
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

func TestUnmarshalHoursAndDiffEncoding(t *testing.T) {
	tests := loadHoursAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("LOCAL_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.LocalHours, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value HoursAndDiffEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalHours != tc.Input.LocalHours {
				t.Errorf("LocalHours = %d, expected %d", value.LocalHours, tc.Input.LocalHours)
			}
			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("TimeDifference.Sign = %d, expected %d", value.TimeDifference.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf("TimeDifference.Hours = %d, expected %d", value.TimeDifference.Hours, tc.Input.DiffHours)
			}
			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf("TimeDifference.Minutes presence = %v, expected %v", value.TimeDifference.Minutes != nil, tc.Input.DiffMinutes != nil)
			} else if value.TimeDifference.Minutes != nil && *value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf("TimeDifference.Minutes = %d, expected %d", *value.TimeDifference.Minutes, *tc.Input.DiffMinutes)
			}
		})
	}
}
)

// HOURS_AND_FRACTION_ENCODING_TC represents a single
// HoursAndFractionEncoding test case from hours_and_fraction_encoding.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see lib/builtin/testing/hours_and_fraction_encoding.py.
type HOURS_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalHoursAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_FRACTION_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := HoursAndFractionEncoding{
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

func TestUnmarshalHoursAndFractionEncoding(t *testing.T) {
	tests := loadHoursAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_FRACTION_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value HoursAndFractionEncoding
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
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
		})
	}
}
)

// HOURS_ENCODING_TC represents a single HoursEncoding test case from
// hours_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/hours_encoding.py.
type HOURS_ENCODING_TC struct {
	Input struct {
		Hours int64 `json:"hours"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalHoursEncoding(t *testing.T) {
	tests := loadHoursEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := HoursEncoding(tc.Input.Hours)

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

func TestUnmarshalHoursEncoding(t *testing.T) {
	tests := loadHoursEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value HoursEncoding
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
)

// HOURS_UTC_AND_FRACTION_ENCODING_TC represents a single
// HoursUtcAndFractionEncoding test case from
// hours_utc_and_fraction_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/hours_utc_and_fraction_encoding.py.
type HOURS_UTC_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalHoursUtcAndFractionEncoding(t *testing.T) {
	tests := loadHoursUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_FRACTION_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := HoursUtcAndFractionEncoding{
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

func TestUnmarshalHoursUtcAndFractionEncoding(t *testing.T) {
	tests := loadHoursUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_FRACTION_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value HoursUtcAndFractionEncoding
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
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
		})
	}
}
)

// HOURS_UTC_ENCODING_TC represents a single HoursUtcEncoding test case
// from hours_utc_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/hours_utc_encoding.py.
type HOURS_UTC_ENCODING_TC struct {
	Input struct {
		Hours int64 `json:"hours"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalHoursUtcEncoding(t *testing.T) {
	tests := loadHoursUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := HoursUtcEncoding(tc.Input.Hours)

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

func TestUnmarshalHoursUtcEncoding(t *testing.T) {
	tests := loadHoursUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_ALIGNED_%v", tc.Input.Hours, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value HoursUtcEncoding
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
)

// MINUTES_AND_DIFF_AND_FRACTION_ENCODING_TC represents a single
// MinutesAndDiffAndFractionEncoding test case from
// minutes_and_diff_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/minutes_and_diff_and_fraction_encoding.py.
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

func loadMinutesAndDiffAndFractionEncodingTestCases(t *testing.T) []MINUTES_AND_DIFF_AND_FRACTION_ENCODING_TC {
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

func TestMarshalMinutesAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HM_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Fraction, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := MinutesAndDiffAndFractionEncoding{
				LocalTime: &MinutesAndDiffAndFractionEncoding_LocalTime{
					Hours:    tc.Input.Hours,
					Minutes:  tc.Input.Minutes,
					Fraction: tc.Input.Fraction,
				},
				TimeDifference: buildTimeDifference(tc.Input.Sign, tc.Input.DiffHours, tc.Input.DiffMinutes),
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

func TestUnmarshalMinutesAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HM_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Fraction, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value MinutesAndDiffAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf("LocalTime.Hours = %d, expected %d", value.LocalTime.Hours, tc.Input.Hours)
			}
			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf("LocalTime.Minutes = %d, expected %d", value.LocalTime.Minutes, tc.Input.Minutes)
			}
			if value.LocalTime.Fraction != tc.Input.Fraction {
				t.Errorf("LocalTime.Fraction = %d, expected %d", value.LocalTime.Fraction, tc.Input.Fraction)
			}
			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("TimeDifference.Sign = %d, expected %d", value.TimeDifference.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf("TimeDifference.Hours = %d, expected %d", value.TimeDifference.Hours, tc.Input.DiffHours)
			}
			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf("TimeDifference.Minutes presence = %v, expected %v", value.TimeDifference.Minutes != nil, tc.Input.DiffMinutes != nil)
			} else if value.TimeDifference.Minutes != nil && *value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf("TimeDifference.Minutes = %d, expected %d", *value.TimeDifference.Minutes, *tc.Input.DiffMinutes)
			}
		})
	}
}
)

// MINUTES_AND_DIFF_ENCODING_TC represents a single MinutesAndDiffEncoding
// test case from minutes_and_diff_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/minutes_and_diff_encoding.py.
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

func TestMarshalMinutesAndDiffEncoding(t *testing.T) {
	tests := loadMinutesAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HM_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := MinutesAndDiffEncoding{
				LocalTime: &MinutesAndDiffEncoding_LocalTime{
					Hours:   tc.Input.Hours,
					Minutes: tc.Input.Minutes,
				},
				TimeDifference: buildTimeDifference(tc.Input.Sign, tc.Input.DiffHours, tc.Input.DiffMinutes),
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

func TestUnmarshalMinutesAndDiffEncoding(t *testing.T) {
	tests := loadMinutesAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HM_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value MinutesAndDiffEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf("LocalTime.Hours = %d, expected %d", value.LocalTime.Hours, tc.Input.Hours)
			}
			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf("LocalTime.Minutes = %d, expected %d", value.LocalTime.Minutes, tc.Input.Minutes)
			}
			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("TimeDifference.Sign = %d, expected %d", value.TimeDifference.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf("TimeDifference.Hours = %d, expected %d", value.TimeDifference.Hours, tc.Input.DiffHours)
			}
			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf("TimeDifference.Minutes presence = %v, expected %v", value.TimeDifference.Minutes != nil, tc.Input.DiffMinutes != nil)
			} else if value.TimeDifference.Minutes != nil && *value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf("TimeDifference.Minutes = %d, expected %d", *value.TimeDifference.Minutes, *tc.Input.DiffMinutes)
			}
		})
	}
}
)

// MINUTES_AND_FRACTION_ENCODING_TC represents a single
// MinutesAndFractionEncoding test case from minutes_and_fraction_encoding.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see lib/builtin/testing/minutes_and_fraction_encoding.py.
type MINUTES_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Minutes  int64 `json:"minutes"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalMinutesAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := MinutesAndFractionEncoding{
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

func TestUnmarshalMinutesAndFractionEncoding(t *testing.T) {
	tests := loadMinutesAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value MinutesAndFractionEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
			if value.Fraction != tc.Input.Fraction {
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
		})
	}
}
)

// MINUTES_ENCODING_TC represents a single MinutesEncoding test case from
// minutes_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/minutes_encoding.py.
type MINUTES_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalMinutesEncoding(t *testing.T) {
	tests := loadMinutesEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_MINUTES_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := MinutesEncoding{
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

func TestUnmarshalMinutesEncoding(t *testing.T) {
	tests := loadMinutesEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_MINUTES_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value MinutesEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
		})
	}
}
)

// MINUTES_UTC_AND_FRACTION_ENCODING_TC represents a single
// MinutesUtcAndFractionEncoding test case from
// minutes_utc_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/minutes_utc_and_fraction_encoding.py.
type MINUTES_UTC_AND_FRACTION_ENCODING_TC struct {
	Input struct {
		Hours    int64 `json:"hours"`
		Minutes  int64 `json:"minutes"`
		Fraction int64 `json:"fraction"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

func loadMinutesUtcAndFractionEncodingTestCases(t *testing.T) []MINUTES_UTC_AND_FRACTION_ENCODING_TC {
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

func TestMarshalMinutesUtcAndFractionEncoding(t *testing.T) {
	tests := loadMinutesUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := MinutesUtcAndFractionEncoding{
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

func TestUnmarshalMinutesUtcAndFractionEncoding(t *testing.T) {
	tests := loadMinutesUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value MinutesUtcAndFractionEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
			if value.Fraction != tc.Input.Fraction {
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
		})
	}
}
)

// MINUTES_UTC_ENCODING_TC represents a single MinutesUtcEncoding test case
// from minutes_utc_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/minutes_utc_encoding.py.
type MINUTES_UTC_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalMinutesUtcEncoding(t *testing.T) {
	tests := loadMinutesUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_MINUTES_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := MinutesUtcEncoding{
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

func TestUnmarshalMinutesUtcEncoding(t *testing.T) {
	tests := loadMinutesUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HOURS_%d_MINUTES_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value MinutesUtcEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
		})
	}
}
)

// TIME_DIFFERENCE_TC represents a single TimeDifference test case from
// time_difference.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/time_difference.py.
type TIME_DIFFERENCE_TC struct {
	Input struct {
		Sign    string `json:"sign"`
		Hours   int64  `json:"hours"`
		Minutes *int64 `json:"minutes"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func timeDifferenceSignFor(sign string) TimeDifferenceSign {
	if sign == "negative" {
		return TIME_DIFFERENCE_SIGN_NEGATIVE
	}
	return TIME_DIFFERENCE_SIGN_POSITIVE
}

func timeDifferenceMinutesLabel(minutes *int64) string {
	if minutes == nil {
		return "NONE"
	}
	return fmt.Sprintf("%d", *minutes)
}

func TestMarshalTimeDifference(t *testing.T) {
	tests := loadTimeDifferenceTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("SIGN_%s_HOURS_%d_MINUTES_%s_ALIGNED_%v", tc.Input.Sign, tc.Input.Hours, timeDifferenceMinutesLabel(tc.Input.Minutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeDifference{
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

func TestUnmarshalTimeDifference(t *testing.T) {
	tests := loadTimeDifferenceTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("SIGN_%s_HOURS_%d_MINUTES_%s_ALIGNED_%v", tc.Input.Sign, tc.Input.Hours, timeDifferenceMinutesLabel(tc.Input.Minutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeDifference
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("Sign = %d, expected %d", value.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.Hours != tc.Input.Hours {
				t.Errorf("Hours = %d, expected %d", value.Hours, tc.Input.Hours)
			}
			if (value.Minutes == nil) != (tc.Input.Minutes == nil) {
				t.Errorf("Minutes presence = %v, expected %v", value.Minutes != nil, tc.Input.Minutes != nil)
			} else if value.Minutes != nil && *value.Minutes != *tc.Input.Minutes {
				t.Errorf("Minutes = %d, expected %d", *value.Minutes, *tc.Input.Minutes)
			}
		})
	}
}
)

// TIME_OF_DAY_AND_DIFF_AND_FRACTION_ENCODING_TC represents a single
// TimeOfDayAndDiffAndFractionEncoding test case from
// time_of_day_and_diff_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/time_of_day_and_diff_and_fraction_encoding.py.
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

func loadTimeOfDayAndDiffAndFractionEncodingTestCases(t *testing.T) []TIME_OF_DAY_AND_DIFF_AND_FRACTION_ENCODING_TC {
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

func TestMarshalTimeOfDayAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HMS_%d_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Fraction, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeOfDayAndDiffAndFractionEncoding{
				LocalTime: &TimeOfDayAndDiffAndFractionEncoding_LocalTime{
					Hours:    tc.Input.Hours,
					Minutes:  tc.Input.Minutes,
					Seconds:  tc.Input.Seconds,
					Fraction: tc.Input.Fraction,
				},
				TimeDifference: buildTimeDifference(tc.Input.Sign, tc.Input.DiffHours, tc.Input.DiffMinutes),
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

func TestUnmarshalTimeOfDayAndDiffAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HMS_%d_%d_%d_F_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Fraction, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeOfDayAndDiffAndFractionEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf("LocalTime.Hours = %d, expected %d", value.LocalTime.Hours, tc.Input.Hours)
			}
			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf("LocalTime.Minutes = %d, expected %d", value.LocalTime.Minutes, tc.Input.Minutes)
			}
			if value.LocalTime.Seconds != tc.Input.Seconds {
				t.Errorf("LocalTime.Seconds = %d, expected %d", value.LocalTime.Seconds, tc.Input.Seconds)
			}
			if value.LocalTime.Fraction != tc.Input.Fraction {
				t.Errorf("LocalTime.Fraction = %d, expected %d", value.LocalTime.Fraction, tc.Input.Fraction)
			}
			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("TimeDifference.Sign = %d, expected %d", value.TimeDifference.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf("TimeDifference.Hours = %d, expected %d", value.TimeDifference.Hours, tc.Input.DiffHours)
			}
			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf("TimeDifference.Minutes presence = %v, expected %v", value.TimeDifference.Minutes != nil, tc.Input.DiffMinutes != nil)
			} else if value.TimeDifference.Minutes != nil && *value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf("TimeDifference.Minutes = %d, expected %d", *value.TimeDifference.Minutes, *tc.Input.DiffMinutes)
			}
		})
	}
}
)

// TIME_OF_DAY_AND_DIFF_ENCODING_TC represents a single
// TimeOfDayAndDiffEncoding test case from time_of_day_and_diff_encoding.json.
// Test vectors are cross-validated against both pycrate and Erlang/OTP's
// asn1 compiler; see lib/builtin/testing/time_of_day_and_diff_encoding.py.
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

func TestMarshalTimeOfDayAndDiffEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HMS_%d_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeOfDayAndDiffEncoding{
				LocalTime: &TimeOfDayAndDiffEncoding_LocalTime{
					Hours:   tc.Input.Hours,
					Minutes: tc.Input.Minutes,
					Seconds: tc.Input.Seconds,
				},
				TimeDifference: buildTimeDifference(tc.Input.Sign, tc.Input.DiffHours, tc.Input.DiffMinutes),
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

func TestUnmarshalTimeOfDayAndDiffEncoding(t *testing.T) {
	tests := loadTimeOfDayAndDiffEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("HMS_%d_%d_%d_SIGN_%s_DIFF_%d_%s_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Sign, tc.Input.DiffHours, timeDifferenceMinutesLabel(tc.Input.DiffMinutes), tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeOfDayAndDiffEncoding
			if tc.Aligned {
				err = value.UnmarshalAPER(data)
			} else {
				err = value.UnmarshalUPER(data)
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}

			if value.LocalTime.Hours != tc.Input.Hours {
				t.Errorf("LocalTime.Hours = %d, expected %d", value.LocalTime.Hours, tc.Input.Hours)
			}
			if value.LocalTime.Minutes != tc.Input.Minutes {
				t.Errorf("LocalTime.Minutes = %d, expected %d", value.LocalTime.Minutes, tc.Input.Minutes)
			}
			if value.LocalTime.Seconds != tc.Input.Seconds {
				t.Errorf("LocalTime.Seconds = %d, expected %d", value.LocalTime.Seconds, tc.Input.Seconds)
			}
			if value.TimeDifference.Sign != timeDifferenceSignFor(tc.Input.Sign) {
				t.Errorf("TimeDifference.Sign = %d, expected %d", value.TimeDifference.Sign, timeDifferenceSignFor(tc.Input.Sign))
			}
			if value.TimeDifference.Hours != tc.Input.DiffHours {
				t.Errorf("TimeDifference.Hours = %d, expected %d", value.TimeDifference.Hours, tc.Input.DiffHours)
			}
			if (value.TimeDifference.Minutes == nil) != (tc.Input.DiffMinutes == nil) {
				t.Errorf("TimeDifference.Minutes presence = %v, expected %v", value.TimeDifference.Minutes != nil, tc.Input.DiffMinutes != nil)
			} else if value.TimeDifference.Minutes != nil && *value.TimeDifference.Minutes != *tc.Input.DiffMinutes {
				t.Errorf("TimeDifference.Minutes = %d, expected %d", *value.TimeDifference.Minutes, *tc.Input.DiffMinutes)
			}
		})
	}
}
)

// TIME_OF_DAY_AND_FRACTION_ENCODING_TC represents a single
// TimeOfDayAndFractionEncoding test case from
// time_of_day_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/time_of_day_and_fraction_encoding.py.
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

func loadTimeOfDayAndFractionEncodingTestCases(t *testing.T) []TIME_OF_DAY_AND_FRACTION_ENCODING_TC {
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

func TestMarshalTimeOfDayAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeOfDayAndFractionEncoding{
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

func TestUnmarshalTimeOfDayAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeOfDayAndFractionEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
			if value.Seconds != tc.Input.Seconds {
				t.Errorf("Seconds = %d, expected %d", value.Seconds, tc.Input.Seconds)
			}
			if value.Fraction != tc.Input.Fraction {
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
		})
	}
}
)

// TIME_OF_DAY_ENCODING_TC represents a single TimeOfDayEncoding test case
// from time_of_day_encoding.json. Test vectors are cross-validated against
// both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/time_of_day_encoding.py.
type TIME_OF_DAY_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
		Seconds int64 `json:"seconds"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalTimeOfDayEncoding(t *testing.T) {
	tests := loadTimeOfDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeOfDayEncoding{
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

func TestUnmarshalTimeOfDayEncoding(t *testing.T) {
	tests := loadTimeOfDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeOfDayEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
			if value.Seconds != tc.Input.Seconds {
				t.Errorf("Seconds = %d, expected %d", value.Seconds, tc.Input.Seconds)
			}
		})
	}
}
)

// TIME_OF_DAY_UTC_AND_FRACTION_ENCODING_TC represents a single
// TimeOfDayUtcAndFractionEncoding test case from
// time_of_day_utc_and_fraction_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/time_of_day_utc_and_fraction_encoding.py.
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

func loadTimeOfDayUtcAndFractionEncodingTestCases(t *testing.T) []TIME_OF_DAY_UTC_AND_FRACTION_ENCODING_TC {
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

func TestMarshalTimeOfDayUtcAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeOfDayUtcAndFractionEncoding{
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

func TestUnmarshalTimeOfDayUtcAndFractionEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcAndFractionEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_F_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Input.Fraction, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeOfDayUtcAndFractionEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
			if value.Seconds != tc.Input.Seconds {
				t.Errorf("Seconds = %d, expected %d", value.Seconds, tc.Input.Seconds)
			}
			if value.Fraction != tc.Input.Fraction {
				t.Errorf("Fraction = %d, expected %d", value.Fraction, tc.Input.Fraction)
			}
		})
	}
}
)

// TIME_OF_DAY_UTC_ENCODING_TC represents a single TimeOfDayUtcEncoding
// test case from time_of_day_utc_encoding.json. Test vectors are
// cross-validated against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/time_of_day_utc_encoding.py.
type TIME_OF_DAY_UTC_ENCODING_TC struct {
	Input struct {
		Hours   int64 `json:"hours"`
		Minutes int64 `json:"minutes"`
		Seconds int64 `json:"seconds"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalTimeOfDayUtcEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := TimeOfDayUtcEncoding{
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

func TestUnmarshalTimeOfDayUtcEncoding(t *testing.T) {
	tests := loadTimeOfDayUtcEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("H_%d_M_%d_S_%d_ALIGNED_%v", tc.Input.Hours, tc.Input.Minutes, tc.Input.Seconds, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value TimeOfDayUtcEncoding
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
				t.Errorf("Minutes = %d, expected %d", value.Minutes, tc.Input.Minutes)
			}
			if value.Seconds != tc.Input.Seconds {
				t.Errorf("Seconds = %d, expected %d", value.Seconds, tc.Input.Seconds)
			}
		})
	}
}
)

// YEAR_DAY_ENCODING_TC represents a single YearDayEncoding test case from
// year_day_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/year_day_encoding.py.
type YEAR_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalYearDayEncoding(t *testing.T) {
	tests := loadYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := YearDayEncoding{
				Year: NewYearEncoding(yearEncodingChoiceForYear(tc.Input.Year)),
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

func TestUnmarshalYearDayEncoding(t *testing.T) {
	tests := loadYearDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value YearDayEncoding
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
			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}
)

// YEAR_WEEK_DAY_ENCODING_TC represents a single YearWeekDayEncoding test
// case from year_week_day_encoding.json. Test vectors are cross-validated
// against both pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/year_week_day_encoding.py.
type YEAR_WEEK_DAY_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
		Day  int64 `json:"day"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalYearWeekDayEncoding(t *testing.T) {
	tests := loadYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := YearWeekDayEncoding{
				Year: NewYearEncoding(yearEncodingChoiceForYear(tc.Input.Year)),
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

func TestUnmarshalYearWeekDayEncoding(t *testing.T) {
	tests := loadYearWeekDayEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_DAY_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Input.Day, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value YearWeekDayEncoding
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
			if value.Week != tc.Input.Week {
				t.Errorf("Week = %d, expected %d", value.Week, tc.Input.Week)
			}
			if value.Day != tc.Input.Day {
				t.Errorf("Day = %d, expected %d", value.Day, tc.Input.Day)
			}
		})
	}
}
)

// YEAR_WEEK_ENCODING_TC represents a single YearWeekEncoding test case from
// year_week_encoding.json. Test vectors are cross-validated against both
// pycrate and Erlang/OTP's asn1 compiler; see
// lib/builtin/testing/year_week_encoding.py.
type YEAR_WEEK_ENCODING_TC struct {
	Input struct {
		Year int64 `json:"year"`
		Week int64 `json:"week"`
	} `json:"input"`
	Output  string `json:"output"`
	Aligned bool   `json:"aligned"`
}

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

func TestMarshalYearWeekEncoding(t *testing.T) {
	tests := loadYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			value := YearWeekEncoding{
				Year: NewYearEncoding(yearEncodingChoiceForYear(tc.Input.Year)),
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

func TestUnmarshalYearWeekEncoding(t *testing.T) {
	tests := loadYearWeekEncodingTestCases(t)

	for _, tc := range tests {
		name := fmt.Sprintf("YEAR_%d_WEEK_%d_ALIGNED_%v", tc.Input.Year, tc.Input.Week, tc.Aligned)
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.Output)
			if err != nil {
				t.Fatalf("Failed to decode input hex: %v", err)
			}

			var value YearWeekEncoding
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
			if value.Week != tc.Input.Week {
				t.Errorf("Week = %d, expected %d", value.Week, tc.Input.Week)
			}
		})
	}
}
