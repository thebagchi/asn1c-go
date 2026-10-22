// Package main runs the convention checkers.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

// _Flag holds the command options and the exit code of a bad flag.
type _Flag struct {
	list     []*analysis.Analyzer
	dir      string
	patterns []string
	changed  bool
	code     int
}

// main runs the convention checkers.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 01:38: print a log line and an error line an agent can read
func main() {
	os.Exit(
		_Run(
			os.Args[1:],
		),
	)
}

// _Run loads the packages, prints each finding, and prints the log line.
// An error makes the process exit 1.
// A warning does not.
// -check selects checkers. The default is every checker.
// -dir selects the module directory. The default is the working directory.
// -changed reads the Go files that differ from HEAD, plus untracked Go files.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
//   - 2026-10-04 11:12: select checks with -check, and name them in the log
//   - 2026-10-21 13:09: read the module directory from -dir
//   - 2026-10-21 20:58: add -changed for the files in the diff
func _Run(args []string) int {
	opt := _Flags(
		args,
	)
	if opt.code != 0 {
		return opt.code
	}

	mode := ""
	if opt.changed {
		mode = "changed"
	}

	err := _Say(
		_Start(
			opt.list,
			mode,
		),
	)
	if err != nil {
		return 1
	}

	if opt.changed {
		return _Changed(
			opt,
		)
	}

	if len(
		opt.patterns,
	) == 0 {
		return _Stop(
			"pass package paths",
			"pass ./...",
		)
	}

	return _Check(
		opt.list,
		opt.dir,
		opt.patterns,
		nil,
	)
}

// _Start builds the log line that names the checkers about to run.
// mode is the word "changed", or empty for a run over the package paths.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
//   - 2026-10-21 20:58: name a changed run in the log
func _Start(
	list []*analysis.Analyzer,
	mode string,
) string {
	text := "check " + Names(
		list,
	)
	if mode != "" {
		text += " " + mode
	}

	return Line(
		LEVEL_LOG,
		"convention",
		text,
		"",
	)
}

// _Changed loads the packages of the diff and drops a finding in an old file.
// No changed Go file is a clean run.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Changed(opt *_Flag) int {
	files, err := common.ChangedGo(
		opt.dir,
	)
	if err != nil {
		return _Stop(
			_Flat(
				err,
			),
			"run this command in a git work tree",
		)
	}

	if len(
		files,
	) == 0 {
		return _Done(
			0,
			0,
			0,
		)
	}

	keep, err := _AbsSet(
		opt.dir,
		files,
	)
	if err != nil {
		return _Stop(
			_Flat(
				err,
			),
			"pass a module directory that exists",
		)
	}

	return _Check(
		opt.list,
		opt.dir,
		_Patterns(
			files,
		),
		keep,
	)
}

// _Flags reads -check, -dir, -changed, and the package paths.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
//   - 2026-10-21 13:09: read the module directory from -dir
//   - 2026-10-21 20:58: read -changed
func _Flags(args []string) *_Flag {
	set := flag.NewFlagSet(
		"convention",
		flag.ContinueOnError,
	)
	set.SetOutput(
		io.Discard,
	)

	var (
		check = set.String(
			"check",
			"",
			"comma-separated checks; the default is all",
		)
		dir = set.String(
			"dir",
			".",
			"directory of the module",
		)
		changed = set.Bool(
			"changed",
			false,
			"read Go files that differ from HEAD",
		)
		err = set.Parse(
			args,
		)
	)
	if err != nil {
		return &_Flag{
			code: _Stop(
				_Flat(
					err,
				),
				"pass -check and package paths",
			),
		}
	}

	return _Use(
		&_Raw{
			check:    *check,
			dir:      *dir,
			changed:  *changed,
			patterns: set.Args(),
		},
	)
}

// _Raw holds the flag values before the checker list is chosen.
type _Raw struct {
	check    string
	dir      string
	changed  bool
	patterns []string
}

// _Use turns the flag values into the checkers and the package paths.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Use(raw *_Raw) *_Flag {
	list, err := Select(
		raw.check,
	)
	if err != nil {
		return &_Flag{
			code: _Stop(
				_Flat(
					err,
				),
				"use "+Names(
					CHECKS,
				),
			),
		}
	}

	if raw.changed && len(
		raw.patterns,
	) > 0 {
		return &_Flag{
			code: _Stop(
				"pass -changed without package paths",
				"drop the package paths",
			),
		}
	}

	return &_Flag{
		list:     list,
		dir:      raw.dir,
		patterns: raw.patterns,
		changed:  raw.changed,
	}
}

// _Check loads the packages and prints the findings.
// keep limits the findings to those files. A nil keep prints every finding.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
//   - 2026-10-21 13:01: load packages through .tools/common
//   - 2026-10-21 13:09: load packages from dir
//   - 2026-10-21 20:58: keep findings in the named files
func _Check(
	list []*analysis.Analyzer,
	dir string,
	patterns []string,
	keep map[string]bool,
) int {
	pkgs, err := common.Load(
		dir,
		patterns,
	)
	if err != nil {
		return _Stop(
			_Flat(
				err,
			),
			"pass a package this module contains",
		)
	}

	graph, err := checker.Analyze(
		list,
		pkgs,
		nil,
	)
	if err != nil {
		return _Stop(
			_Flat(
				err,
			),
			"repair the checker input",
		)
	}

	return _Finish(
		graph,
		len(
			pkgs,
		),
		keep,
	)
}

// _Finish prints the findings and the closing log line.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
//   - 2026-10-21 20:58: pass the file set through to the printer
func _Finish(
	graph *checker.Graph,
	count int,
	keep map[string]bool,
) int {
	errors, warnings, err := _Print(
		os.Stderr,
		graph,
		keep,
	)
	if err != nil {
		return 1
	}

	return _Done(
		count,
		errors,
		warnings,
	)
}

// _Done prints the closing log line and returns the exit code.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Done(
	count int,
	errors int,
	warnings int,
) int {
	err := _Say(
		_End(
			count,
			errors,
			warnings,
		),
	)
	if err != nil {
		return 1
	}

	if errors > 0 {
		return 1
	}

	return 0
}

// _End builds the log line of counts.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _End(
	count int,
	errors int,
	warnings int,
) string {
	return Line(
		LEVEL_LOG,
		"convention",
		fmt.Sprintf(
			"%d packages, %d errors, %d warnings",
			count,
			errors,
			warnings,
		),
		"",
	)
}

// _Flat turns a multiline error into one line.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
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
//   - 2026-10-04 01:38: initial creation
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
//   - 2026-10-04 01:38: initial creation
func _Stop(
	message string,
	fix string,
) int {
	err := _Say(
		Line(
			LEVEL_ERROR,
			"convention",
			message,
			fix,
		),
	)
	if err != nil {
		return 1
	}

	return 1
}
