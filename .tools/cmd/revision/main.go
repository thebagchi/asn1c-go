// Package main checks the new row in revision.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// main checks the new row in revision.md.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func main() {
	os.Exit(
		_Run(
			os.Args[1:],
		),
	)
}

// _Run reads -dir and prints each problem.
// A work tree with no open change exits 0.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Run(args []string) int {
	dir, code := _Flags(
		args,
	)
	if code != 0 {
		return code
	}

	err := _Say(
		_Line(
			LEVEL_LOG,
			"check",
			"",
		),
	)
	if err != nil {
		return 1
	}

	return _Report(
		dir,
	)
}

// _Report prints the problems and the closing log line.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Report(dir string) int {
	problems, err := _Problems(
		dir,
	)
	if err != nil {
		return _Stop(
			_Flat(
				err,
			),
			"run this command in a git work tree",
		)
	}

	if problems == nil {
		return _SayCode(
			_Line(
				LEVEL_LOG,
				"no open change",
				"",
			),
		)
	}

	for _, problem := range problems {
		err = _Say(
			problem,
		)
		if err != nil {
			return 1
		}
	}

	return _Done(
		len(
			problems,
		),
	)
}

// _Flags reads -dir.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Flags(args []string) (string, int) {
	set := flag.NewFlagSet(
		"revision",
		flag.ContinueOnError,
	)
	set.SetOutput(
		io.Discard,
	)

	var (
		dir = set.String(
			"dir",
			".",
			"directory of the module",
		)
		err = set.Parse(
			args,
		)
	)
	if err != nil {
		return "", _Stop(
			_Flat(
				err,
			),
			"pass -dir",
		)
	}

	if len(
		set.Args(),
	) > 0 {
		return "", _Stop(
			"pass -dir without extra arguments",
			"drop the extra arguments",
		)
	}

	return *dir, 0
}

// _Done prints the closing log line.
// A problem makes the process exit 1.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Done(count int) int {
	err := _Say(
		_Line(
			LEVEL_LOG,
			fmt.Sprintf(
				"%d errors",
				count,
			),
			"",
		),
	)
	if err != nil {
		return 1
	}

	if count > 0 {
		return 1
	}

	return 0
}

// _SayCode writes one log line and exits 0.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _SayCode(text string) int {
	err := _Say(
		text,
	)
	if err != nil {
		return 1
	}

	return 0
}

// _Flat turns a multiline error into one line.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Flat(err error) string {
	return strings.ReplaceAll(
		err.Error(),
		"\n",
		" ",
	)
}

// _Say writes one line to the error stream.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Say(text string) error {
	_, err := fmt.Fprintln(
		os.Stderr,
		text,
	)

	return err
}

// _Stop writes one error and returns the failure code.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Stop(
	message string,
	fix string,
) int {
	err := _Say(
		_Line(
			LEVEL_ERROR,
			message,
			fix,
		),
	)
	if err != nil {
		return 1
	}

	return 1
}
