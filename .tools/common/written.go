package common

import "go/ast"

// Written reports whether file is hand-written.
// A generated file has the banner, so the layout gates skip it.
//
// Revisions:
//   - 2026-10-21 13:01: initial creation
func Written(file *ast.File) bool {
	return !ast.IsGenerated(
		file,
	)
}
