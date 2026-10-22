package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	LEVEL_ERROR = "error"
	LEVEL_LOG   = "log"
)

// _Opt holds the question the command answers.
type _Opt struct {
	dir      string
	name     string
	pkg      string
	changed  bool
	patterns []string
	code     int
}

// main answers one call-graph question.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func main() {
	os.Exit(
		_Run(
			os.Args[1:],
		),
	)
}

// _Run reads the flags and prints each edge.
// An edge is not an error. A load failure is an error.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Run(args []string) int {
	opt := _Flags(
		args,
	)
	if opt.code != 0 {
		return opt.code
	}

	err := _Say(
		_Line(
			LEVEL_LOG,
			_Title(
				opt,
			),
			"",
		),
	)
	if err != nil {
		return 1
	}

	lines, err := _Edges(
		opt,
	)
	if err != nil {
		return _Stop(
			_Flat(
				err,
			),
			"pass a package this module contains",
		)
	}

	for _, line := range lines {
		err = _Say(
			line,
		)
		if err != nil {
			return 1
		}
	}

	return _Done(
		len(
			lines,
		),
	)
}

// _Title names the question in the first log line.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Title(opt *_Opt) string {
	if opt.changed {
		return "changed"
	}

	text := "call " + opt.name
	if opt.pkg == "" {
		return text
	}

	return text + " in " + opt.pkg
}

// _Flags reads -dir, -name, -pkg, -changed, and the package paths.
// -name and -changed are two questions. The command accepts one of them.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Flags(args []string) *_Opt {
	bound := _Bind(
		args,
	)
	if bound.err != nil {
		return &_Opt{
			code: _Stop(
				_Flat(
					bound.err,
				),
				"pass -name or -changed",
			),
		}
	}

	return _Question(
		&_Opt{
			dir:     bound.dir,
			name:    bound.name,
			pkg:     bound.pkg,
			changed: bound.changed,
		},
		bound.patterns,
	)
}

// _Bound holds the flag values after a parse.
type _Bound struct {
	dir      string
	name     string
	pkg      string
	changed  bool
	patterns []string
	err      error
}

// _Bind parses the flags.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Bind(args []string) *_Bound {
	set := flag.NewFlagSet(
		"graph",
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
		name = set.String(
			"name",
			"",
			"callee name",
		)
		pkg = set.String(
			"pkg",
			"",
			"callee package path or package name",
		)
		changed = set.Bool(
			"changed",
			false,
			"callers of functions defined in the diff",
		)
		err = set.Parse(
			args,
		)
	)
	if err != nil {
		return &_Bound{
			err: err,
		}
	}

	return &_Bound{
		dir:      *dir,
		name:     *name,
		pkg:      *pkg,
		changed:  *changed,
		patterns: set.Args(),
	}
}

// _Question checks that the command asks one question.
// A name query with no package path reads ./...
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Question(
	opt *_Opt,
	patterns []string,
) *_Opt {
	gotName := opt.name != ""
	if gotName == opt.changed {
		return &_Opt{
			code: _Stop(
				"pass -name or -changed",
				"use one of them",
			),
		}
	}

	opt.patterns = patterns
	if len(
		opt.patterns,
	) == 0 && !opt.changed {
		opt.patterns = []string{"./..."}
	}

	return opt
}

// _Done prints the edge count and exits 0.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Done(count int) int {
	err := _Say(
		_Line(
			LEVEL_LOG,
			fmt.Sprintf(
				"%d edges",
				count,
			),
			"",
		),
	)
	if err != nil {
		return 1
	}

	return 0
}

// _Flat turns a multiline error into one line.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Flat(err error) string {
	return strings.ReplaceAll(
		err.Error(),
		"\n",
		" ",
	)
}

// _Line builds one line an agent can read.
// An empty fix omits the fix clause.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Line(
	level string,
	message string,
	fix string,
) string {
	text := level + ": graph: " + message
	if fix == "" {
		return text
	}

	return text + ". fix: " + fix
}

// _Say writes one line to the error stream.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
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
//   - 2026-10-21 21:16: initial creation
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
