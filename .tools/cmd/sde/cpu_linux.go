//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	CPUINFO_PATH = "/proc/cpuinfo"
)

// _Host reports whether this CPU has feature.
// An empty feature does not read cpuinfo, because install does not need it.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Host(feature string) (bool, error) {
	if feature == "" {
		return false, nil
	}

	flags, err := _CPUFlags()
	if err != nil {
		return false, err
	}

	return _Supports(
		flags,
		feature,
	), nil
}

// _CPUFlags is the first flags line in cpuinfo.
// Each processor repeats that line. The first line is enough.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _CPUFlags() (string, error) {
	data, err := os.ReadFile(CPUINFO_PATH)
	if err != nil {
		return "", err
	}

	for line := range strings.SplitSeq(
		string(data),
		"\n",
	) {
		name, values, ok := strings.Cut(
			line,
			":",
		)
		if !ok {
			continue
		}

		if strings.TrimSpace(name) != "flags" {
			continue
		}

		return strings.TrimSpace(values), nil
	}

	return "", fmt.Errorf("cpuinfo has no flags")
}
