package main

import (
	"fmt"
	"strings"
)

const (
	FEATURE_AVX2   = "avx2"
	FEATURE_AVX512 = "avx512"
	FEATURE_GFNI   = "gfni"
	CHIP_HSW       = "-hsw"
	CHIP_ICL       = "-icl"
	FLAG_AVX2      = "avx2"
	FLAG_AVX512F   = "avx512f"
	FLAG_AVX512BW  = "avx512bw"
	FLAG_GFNI      = "gfni"
	ARG_INSTALL    = "install"
	MODE_INSTALL   = "install"
	MODE_NATIVE    = "native"
	MODE_SDE       = "sde"
	MIX_FLAG       = "-mix"
	MIX_FILE_FLAG  = "-omix"
	MIX_FILE       = "sde-mix-out.txt"
	LEVEL_LOG      = "log"
	LEVEL_ERROR    = "error"
)

// _Ask is the question: which feature, whether to count, and the program.
type _Ask struct {
	feature string
	count   bool
	program []string
}

// _Known is the question plus whether this CPU has the feature.
type _Known struct {
	ask  *_Ask
	have bool
}

// _Step is how to run that question.
type _Step struct {
	mode string
	chip string
	mix  bool
}

// _Decide selects a native run, an SDE run, or an install.
// A count always uses SDE, because the mix is the product.
// A native run stays on this CPU, so its time stays a CPU time.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Decide(known *_Known) (*_Step, error) {
	ask := known.ask
	if ask.feature == "" {
		return _Bare(ask)
	}

	chip, found := _Chip(ask.feature)
	if !found {
		return nil, fmt.Errorf(
			"unknown feature %s, use %s, %s, or %s",
			ask.feature,
			FEATURE_AVX2,
			FEATURE_AVX512,
			FEATURE_GFNI,
		)
	}

	if len(ask.program) == 0 {
		return nil, fmt.Errorf("pass the program after --")
	}

	if ask.count || !known.have {
		return &_Step{
			mode: MODE_SDE,
			chip: chip,
			mix:  ask.count,
		}, nil
	}

	return &_Step{
		mode: MODE_NATIVE,
	}, nil
}

// _Bare is the command with no -feature: install, or an error.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Bare(ask *_Ask) (*_Step, error) {
	if ask.count {
		return nil, fmt.Errorf("-count needs -feature")
	}

	if len(ask.program) == 0 {
		return &_Step{
			mode: MODE_INSTALL,
		}, nil
	}

	if ask.program[0] != ARG_INSTALL {
		return nil, fmt.Errorf("pass -feature or install")
	}

	if len(ask.program) != 1 {
		return nil, fmt.Errorf("install takes no arguments")
	}

	return &_Step{
		mode: MODE_INSTALL,
	}, nil
}

// _Chip is the SDE chip flag for feature.
// avx512 and gfni share Ice Lake, because that chip has AVX512BW and GFNI.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Chip(feature string) (string, bool) {
	switch feature {
	case FEATURE_AVX2:
		return CHIP_HSW, true
	case FEATURE_AVX512, FEATURE_GFNI:
		return CHIP_ICL, true
	default:
		return "", false
	}
}

// _Supports reports whether flags, a cpuinfo flags line, contain feature.
// avx512 needs both AVX512F and AVX512BW, the same pair HAS_AVX512 requires.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Supports(
	flags string,
	feature string,
) bool {
	words := _Words(flags)

	switch feature {
	case FEATURE_AVX2:
		return words[FLAG_AVX2]
	case FEATURE_AVX512:
		return words[FLAG_AVX512F] && words[FLAG_AVX512BW]
	case FEATURE_GFNI:
		return words[FLAG_GFNI]
	default:
		return false
	}
}

// _Words is the set of tokens in a cpuinfo flags line.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Words(flags string) map[string]bool {
	words := map[string]bool{}
	for _, word := range strings.Fields(flags) {
		words[word] = true
	}

	return words
}
