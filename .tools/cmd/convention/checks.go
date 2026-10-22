package main

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// CHECKS is every checker, in the order a log line names them.
var (
	CHECKS = []*analysis.Analyzer{
		REVISION,
		LEAD,
		SNAKE,
		FIELDS,
		GUARD,
		BODY,
		DECLARE,
		LITERAL,
		CALL,
		POINTER,
		BANNER,
	}
)

// Select returns the named checkers, in CHECKS order.
// An empty list returns every checker.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func Select(list string) ([]*analysis.Analyzer, error) {
	text := strings.TrimSpace(
		list,
	)
	if text == "" {
		return CHECKS, nil
	}

	want, err := _Want(
		text,
	)
	if err != nil {
		return nil, err
	}

	return _Chosen(
		want,
	), nil
}

// Names joins checker names with one space.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func Names(list []*analysis.Analyzer) string {
	var parts []string

	for _, checker := range list {
		parts = append(
			parts,
			checker.Name,
		)
	}

	return strings.Join(
		parts,
		" ",
	)
}

// _Want reads a comma-separated list of checker names.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Want(text string) (map[string]bool, error) {
	var (
		known = _Known()
		want  = map[string]bool{}
	)

	for _, name := range strings.Split(
		text,
		",",
	) {
		name = strings.TrimSpace(
			name,
		)
		if name == "" {
			continue
		}

		if !known[name] {
			return nil, _Unknown(
				name,
			)
		}

		want[name] = true
	}

	if len(
		want,
	) == 0 {
		return nil, _Unknown(
			text,
		)
	}

	return want, nil
}

// _Unknown reports one name that is not a checker.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Unknown(name string) error {
	return fmt.Errorf(
		"unknown check %s",
		name,
	)
}

// _Known returns the checker names.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Known() map[string]bool {
	known := map[string]bool{}

	for _, checker := range CHECKS {
		known[checker.Name] = true
	}

	return known
}

// _Chosen returns the checkers whose names are in want, in CHECKS order.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Chosen(want map[string]bool) []*analysis.Analyzer {
	var out []*analysis.Analyzer

	for _, checker := range CHECKS {
		if !want[checker.Name] {
			continue
		}

		out = append(
			out,
			checker,
		)
	}

	return out
}
