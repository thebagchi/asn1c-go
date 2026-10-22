package common

import (
	"slices"
	"strings"
)

// ChangedGo returns the Go files that differ from HEAD, plus untracked Go files.
// Each path uses a forward slash and stays relative to dir.
// An empty list means the work tree has no such file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func ChangedGo(dir string) ([]string, error) {
	tracked, err := Git(
		dir,
		"diff",
		"--name-only",
		"--diff-filter=ACMR",
		"HEAD",
		"--",
		"*.go",
	)
	if err != nil {
		return nil, err
	}

	extra, err := Git(
		dir,
		"ls-files",
		"--others",
		"--exclude-standard",
		"--",
		"*.go",
	)
	if err != nil {
		return nil, err
	}

	return _Merge(
		tracked,
		extra,
	), nil
}

// _Merge returns the unique paths from the two git listings, in order.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Merge(
	tracked string,
	extra string,
) []string {
	seen := map[string]bool{}

	var files []string
	for _, text := range []string{tracked, extra} {
		files = _Paths(
			files,
			seen,
			text,
		)
	}

	slices.Sort(
		files,
	)

	return files
}

// _Paths appends each non-empty path from one git listing.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Paths(
	files []string,
	seen map[string]bool,
	text string,
) []string {
	for _, line := range strings.Split(
		text,
		"\n",
	) {
		path := strings.TrimSpace(
			strings.ReplaceAll(
				line,
				"\\",
				"/",
			),
		)
		if path == "" || seen[path] {
			continue
		}

		seen[path] = true
		files = append(
			files,
			path,
		)
	}

	return files
}
