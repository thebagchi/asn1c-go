// Package main runs the fold tool.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// EXIT_ERROR is the exit code of a failed run.
const (
	EXIT_ERROR = 2
)

// main runs the fold tool.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func main() {
	os.Exit(
		_Run(
			os.Args[1:],
		),
	)
}

// _Run folds the packages named in args.
// Without -w it prints each file that would change and returns 1 when there is one.
// With -w it writes each such file and returns 0.
// An error gives 2.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Run(args []string) int {
	set := flag.NewFlagSet(
		"fold",
		flag.ContinueOnError,
	)
	set.SetOutput(
		io.Discard,
	)

	var (
		write = set.Bool(
			"w",
			false,
			"write the folded files",
		)
		err = set.Parse(
			args,
		)
	)
	if err == nil && set.NArg() == 0 {
		err = fmt.Errorf(
			"pass at least one package path",
		)
	}

	if err != nil {
		return _Stop(
			err,
		)
	}

	paths, out, err := _Fold(
		set.Args(),
	)
	if err != nil {
		return _Stop(
			err,
		)
	}

	if *write {
		return _Write(
			paths,
			out,
		)
	}

	return _List(
		paths,
	)
}

// _Fold folds the packages and returns the changed files, sorted by path.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Fold(patterns []string) ([]string, map[string][]byte, error) {
	out, err := Fold(
		".",
		patterns,
	)
	if err != nil {
		return nil, nil, err
	}

	paths := make(
		[]string,
		0,
		len(out),
	)
	for path := range out {
		paths = append(
			paths,
			path,
		)
	}

	sort.Strings(
		paths,
	)

	return paths, out, nil
}

// _List prints the path of each file and returns 1 when there is one.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _List(paths []string) int {
	for _, path := range paths {
		fmt.Println(
			_Short(
				path,
			),
		)
	}

	if len(
		paths,
	) > 0 {
		return 1
	}

	return 0
}

// _Write replaces each file with its folded source and keeps the file mode.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Write(
	paths []string,
	out map[string][]byte,
) int {
	for _, path := range paths {
		info, err := os.Stat(
			path,
		)
		if err == nil {
			err = os.WriteFile(
				path,
				out[path],
				info.Mode().Perm(),
			)
		}

		if err != nil {
			return _Stop(
				err,
			)
		}
	}

	return 0
}

// _Short returns path relative to the working directory when it can.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Short(path string) string {
	dir, err := os.Getwd()
	if err != nil {
		return path
	}

	rel, err := filepath.Rel(
		dir,
		path,
	)
	if err != nil {
		return path
	}

	return rel
}

// _Stop prints one error line and returns the failure code.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Stop(err error) int {
	fmt.Fprintf(
		os.Stderr,
		"fold: error: %s\n",
		err,
	)

	return EXIT_ERROR
}
