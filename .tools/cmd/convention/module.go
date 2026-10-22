package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// _Module returns the module path from the analyser flag or from go.mod.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Module(pass *analysis.Pass) (string, error) {
	flag := pass.Analyzer.Flags.Lookup(
		"module",
	)
	if flag != nil && flag.Value.String() != "" {
		return flag.Value.String(), nil
	}

	return _ReadModule()
}

// _ReadModule reads the module line from the nearest go.mod.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _ReadModule() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		var (
			path = filepath.Join(
				dir,
				"go.mod",
			)
			line, err = _ModuleLine(
				path,
			)
		)
		if err == nil {
			return line, nil
		}

		if !os.IsNotExist(
			err,
		) {
			return "", err
		}

		parent := filepath.Dir(
			dir,
		)
		if parent == dir {
			return "", fmt.Errorf(
				"go.mod not found",
			)
		}

		dir = parent
	}
}

// _ModuleLine returns the path named by the module line of one go.mod.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _ModuleLine(path string) (string, error) {
	file, err := os.Open(
		path,
	)
	if err != nil {
		return "", err
	}

	line, err := _ScanModule(
		file,
	)

	return line, _First(
		err,
		file.Close(),
	)
}

// _First returns the first error, and the second when the first is nil.
//
// Revisions:
//   - 2026-10-04 00:14: initial creation
func _First(
	err error,
	late error,
) error {
	if err != nil {
		return err
	}

	return late
}

// _ScanModule returns the module path from an open go.mod.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _ScanModule(file *os.File) (string, error) {
	scanner := bufio.NewScanner(
		file,
	)

	for scanner.Scan() {
		fields := strings.Fields(
			scanner.Text(),
		)
		if len(
			fields,
		) >= 2 && fields[0] == "module" {
			return fields[1], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf(
		"go.mod has no module path",
	)
}
