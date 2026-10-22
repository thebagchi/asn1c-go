// Package main rewrites Go source so that the call and literal checks of
// .tools/cmd/convention report nothing.
package main

import (
	"fmt"
	"go/ast"
	"os"

	"golang.org/x/tools/go/packages"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

// Fold loads the packages that match patterns, from dir, tests included, and
// returns the folded source of each file that changes, keyed by its absolute
// path.
// A file that needs no change is absent from the map.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
//   - 2026-10-21 13:01: load packages through .tools/common
func Fold(
	dir string,
	patterns []string,
) (map[string][]byte, error) {
	pkgs, err := common.Load(
		dir,
		patterns,
	)
	if err != nil {
		return nil, err
	}

	var (
		out  = map[string][]byte{}
		seen = map[string]bool{}
	)

	for _, pkg := range pkgs {
		err = _Package(
			pkg,
			seen,
			out,
		)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

// _Package folds each file of one package that no earlier package has folded.
// The package and its test variant share files, so seen keeps each path once.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Package(
	pkg *packages.Package,
	seen map[string]bool,
	out map[string][]byte,
) error {
	for _, file := range pkg.Syntax {
		path := pkg.Fset.File(
			file.Pos(),
		).Name()
		if seen[path] || !common.Written(
			file,
		) {
			continue
		}

		seen[path] = true

		data, err := _File(
			pkg,
			file,
			path,
		)
		if err != nil {
			return err
		}

		if data != nil {
			out[path] = data
		}
	}

	return nil
}

// _File returns the folded source of one file, or nil when the file does not change.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _File(
	pkg *packages.Package,
	file *ast.File,
	path string,
) ([]byte, error) {
	src, err := os.ReadFile(
		path,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read %s: %w",
			path,
			err,
		)
	}

	edits := _Edits(
		pkg,
		file,
		src,
	)
	if len(
		edits,
	) == 0 {
		return nil, nil
	}

	return _Render(
		path,
		src,
		edits,
	)
}
