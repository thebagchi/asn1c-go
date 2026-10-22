// This file is an internal test because _Decide and _Supports are unexported.
package main

import "testing"

// TestRegression_Feature checks the chip, the native run, and the mix.
// A CPU that has the feature stays native. -count always selects SDE.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func TestRegression_Feature(t *testing.T) {
	var (
		program = []string{
			"go",
			"test",
		}
		rows = []*struct {
			name    string
			feature string
			count   bool
			have    bool
			args    []string
			mode    string
			chip    string
			mix     bool
			err     string
		}{
			{
				name:    "native avx512",
				feature: FEATURE_AVX512,
				have:    true,
				args:    program,
				mode:    MODE_NATIVE,
			},
			{
				name:    "missing avx512",
				feature: FEATURE_AVX512,
				args:    program,
				mode:    MODE_SDE,
				chip:    CHIP_ICL,
			},
			{
				name:    "count on a cpu that has it",
				feature: FEATURE_AVX512,
				count:   true,
				have:    true,
				args:    program,
				mode:    MODE_SDE,
				chip:    CHIP_ICL,
				mix:     true,
			},
			{
				name:    "avx2",
				feature: FEATURE_AVX2,
				args:    program,
				mode:    MODE_SDE,
				chip:    CHIP_HSW,
			},
			{
				name:    "gfni",
				feature: FEATURE_GFNI,
				have:    true,
				args:    program,
				mode:    MODE_NATIVE,
			},
			{
				name: "install",
				mode: MODE_INSTALL,
			},
			{
				name: "install argument",
				args: []string{ARG_INSTALL},
				mode: MODE_INSTALL,
			},
			{
				name: "install extra",
				args: []string{
					ARG_INSTALL,
					"more",
				},
				err: "install takes no arguments",
			},
			{
				name:  "count without feature",
				count: true,
				err:   "-count needs -feature",
			},
			{
				name:    "program missing",
				feature: FEATURE_AVX512,
				err:     "pass the program after --",
			},
			{
				name:    "unknown feature",
				feature: "sse2",
				args:    program,
				err:     "unknown feature sse2, use avx2, avx512, or gfni",
			},
			{
				name: "bare program",
				args: program,
				err:  "pass -feature or install",
			},
		}
	)

	for _, row := range rows {
		t.Run(
			row.name,
			func(t *testing.T) {
				step, err := _Decide(
					&_Known{
						ask: &_Ask{
							feature: row.feature,
							count:   row.count,
							program: row.args,
						},
						have: row.have,
					},
				)
				if row.err != "" {
					if err == nil || err.Error() != row.err {
						t.Fatalf(
							"error %v, want %s",
							err,
							row.err,
						)
					}

					return
				}

				if err != nil {
					t.Fatalf(
						"decide: %v",
						err,
					)
				}

				same := step.mode == row.mode
				same = same && step.chip == row.chip
				same = same && step.mix == row.mix

				if !same {
					t.Fatalf(
						"mode %s chip %s mix %t, want %s %s %t",
						step.mode,
						step.chip,
						step.mix,
						row.mode,
						row.chip,
						row.mix,
					)
				}
			},
		)
	}
}

// TestRegression_Supports checks the cpuinfo words for each feature.
// avx512 needs both AVX512F and AVX512BW. A prefix of a flag is not a match.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func TestRegression_Supports(t *testing.T) {
	var (
		rows = []*struct {
			name    string
			flags   string
			feature string
			want    bool
		}{
			{
				name:    "avx2",
				flags:   "fpu avx avx2 bmi2",
				feature: FEATURE_AVX2,
				want:    true,
			},
			{
				name:    "avx is not avx2",
				flags:   "avx",
				feature: FEATURE_AVX2,
				want:    false,
			},
			{
				name:    "avx512 pair",
				flags:   "avx512f avx512bw",
				feature: FEATURE_AVX512,
				want:    true,
			},
			{
				name:    "avx512f alone",
				flags:   "avx512f",
				feature: FEATURE_AVX512,
				want:    false,
			},
			{
				name:    "gfni",
				flags:   "gfni avx2",
				feature: FEATURE_GFNI,
				want:    true,
			},
			{
				name:    "unknown",
				flags:   "avx2",
				feature: "sse2",
				want:    false,
			},
		}
	)

	for _, row := range rows {
		t.Run(
			row.name,
			func(t *testing.T) {
				got := _Supports(
					row.flags,
					row.feature,
				)
				if got != row.want {
					t.Fatalf(
						"_Supports() = %t, want %t",
						got,
						row.want,
					)
				}
			},
		)
	}
}
