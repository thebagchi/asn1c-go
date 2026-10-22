package main

import (
	"path/filepath"
)

// _Patterns returns one package path for each directory that holds a changed file.
// A file in the module root selects the package ".".
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Patterns(files []string) []string {
	seen := map[string]bool{}

	var patterns []string

	for _, file := range files {
		pattern := _Pattern(
			file,
		)
		if seen[pattern] {
			continue
		}

		seen[pattern] = true
		patterns = append(
			patterns,
			pattern,
		)
	}

	return patterns
}

// _Pattern returns the package path of the directory that holds file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Pattern(file string) string {
	dir := filepath.ToSlash(
		filepath.Dir(
			file,
		),
	)
	if dir == "." {
		return "."
	}

	return "./" + dir
}

// _AbsSet returns the absolute path of each file, keyed for a lookup.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _AbsSet(
	dir string,
	files []string,
) (map[string]bool, error) {
	root, err := filepath.Abs(
		dir,
	)
	if err != nil {
		return nil, err
	}

	set := map[string]bool{}

	for _, file := range files {
		path := filepath.Join(
			root,
			filepath.FromSlash(
				file,
			),
		)
		set[filepath.Clean(
			path,
		)] = true
	}

	return set, nil
}
