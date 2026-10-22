package main

import (
	"fmt"
	"go/token"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis/checker"
)

// _Print writes each finding.
// It returns the error count, the warning count, and a write error.
// keep drops a finding whose file is absent from the set. A nil keep prints every finding.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
//   - 2026-10-21 20:58: drop a finding that is outside keep
func _Print(
	w io.Writer,
	graph *checker.Graph,
	keep map[string]bool,
) (int, int, error) {
	lines := _Lines(
		graph,
		keep,
	)
	slices.Sort(
		lines,
	)

	var (
		errors   = 0
		warnings = 0
	)

	for _, line := range lines {
		err := _Write(
			w,
			_Show(
				line,
			),
		)
		if err != nil {
			return errors, warnings, err
		}

		e, warn := Count(
			_Body(
				line,
			),
		)
		errors += e
		warnings += warn
	}

	return errors, warnings, nil
}

// _Write writes one rendered line.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func _Write(
	w io.Writer,
	line string,
) error {
	_, err := fmt.Fprintln(
		w,
		line,
	)

	return err
}

// _Lines collects one record for each finding.
// A record holds the position, a tab, and the finding text.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
//   - 2026-10-21 20:58: pass the file set through
func _Lines(
	graph *checker.Graph,
	keep map[string]bool,
) []string {
	seen := map[string]bool{}

	var lines []string
	for _, act := range graph.Roots {
		lines = _FromAction(
			lines,
			seen,
			act,
			keep,
		)
	}

	return lines
}

// _FromAction appends the findings of one analyser on one package.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
//   - 2026-10-21 20:58: pass the file set through
func _FromAction(
	lines []string,
	seen map[string]bool,
	act *checker.Action,
	keep map[string]bool,
) []string {
	if act.Err != nil {
		return _Push(
			lines,
			seen,
			"\t"+_ActionErr(
				act,
			),
		)
	}

	for _, diag := range act.Diagnostics {
		if !_Wanted(
			act,
			diag.Pos,
			keep,
		) {
			continue
		}

		lines = _Push(
			lines,
			seen,
			_Where(
				act,
				diag.Pos,
			)+"\t"+diag.Message,
		)
	}

	return lines
}

// _ActionErr formats one analyser failure.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _ActionErr(act *checker.Action) string {
	return Line(
		LEVEL_ERROR,
		act.Analyzer.Name,
		strings.ReplaceAll(
			act.Err.Error(),
			"\n",
			" ",
		),
		"repair the input the checker could not read",
	)
}

// _Wanted reports whether the finding stays in the report.
// A nil keep keeps every finding. A finding with no file position stays out of a changed run.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Wanted(
	act *checker.Action,
	pos token.Pos,
	keep map[string]bool,
) bool {
	if keep == nil {
		return true
	}

	at := act.Package.Fset.Position(
		pos,
	)
	if !at.IsValid() {
		return false
	}

	return keep[filepath.Clean(
		at.Filename,
	)]
}

// _Where renders a position, or "" when the position is not valid.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Where(
	act *checker.Action,
	pos token.Pos,
) string {
	at := act.Package.Fset.Position(
		pos,
	)
	if !at.IsValid() {
		return ""
	}

	return at.String()
}

// _Push appends line when the set has not seen it.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func _Push(
	lines []string,
	seen map[string]bool,
	line string,
) []string {
	if seen[line] {
		return lines
	}

	seen[line] = true

	return append(
		lines,
		line,
	)
}

// _Show renders a record as one line an agent can read.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func _Show(line string) string {
	pos, text, ok := strings.Cut(
		line,
		"\t",
	)
	if !ok || pos == "" {
		return text
	}

	return pos + ": " + text
}

// _Body returns the finding text from a record.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func _Body(line string) string {
	_, text, ok := strings.Cut(
		line,
		"\t",
	)
	if !ok {
		return line
	}

	return text
}
