package main

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// REVISION reports a function whose doc comment has no revision history.
var (
	REVISION = _New(
		"revision",
		"revision reports a function whose doc comment has no revision history",
		_RunRevision,
	)
)

// _RunRevision reports each function whose revision history is missing or wrong.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-21 16:36: report each bullet that lacks the two-space indent
func _RunRevision(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}

				_Revision(
					pass,
					fn,
				)

				_ReportIndent(
					pass,
					fn,
				)
			}
		},
	)

	return nil, nil
}

// _Revision reports one function when its doc comment breaks the revision rule.
// The first bullet opens with the local time to the minute and names initial creation.
// The two parts are separate findings, so each one names its own fix.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 01:38: report an error line with the rule and the fix
//   - 2026-10-21 15:34: report a first bullet with no time to the minute
func _Revision(
	pass *analysis.Pass,
	fn *ast.FuncDecl,
) {
	if fn.Doc == nil {
		_Fail(
			pass,
			fn.Name.Pos(),
			NO_HISTORY,
			FIX_HISTORY,
		)

		return
	}

	entry, ok := _FirstEntry(
		fn.Doc,
	)
	if !ok {
		_Fail(
			pass,
			fn.Name.Pos(),
			NO_HISTORY,
			FIX_HISTORY,
		)

		return
	}

	if !TIME_FORM.MatchString(
		entry,
	) {
		_Fail(
			pass,
			fn.Name.Pos(),
			NO_TIME,
			FIX_TIME,
		)
	}

	if !strings.Contains(
		entry,
		"initial creation",
	) {
		_Fail(
			pass,
			fn.Name.Pos(),
			NOT_INITIAL,
			FIX_INITIAL,
		)
	}
}

// _FirstEntry returns the text of the first Revisions bullet.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _FirstEntry(doc *ast.CommentGroup) (string, bool) {
	seen := false

	for _, comment := range doc.List {
		line := strings.TrimSpace(
			strings.TrimPrefix(
				comment.Text,
				"//",
			),
		)
		if line == REVISIONS {
			seen = true

			continue
		}

		if !seen {
			continue
		}

		match := BULLET_FORM.FindStringSubmatch(
			line,
		)
		if match == nil {
			continue
		}

		return match[1], true
	}

	return "", false
}

// _ReportIndent reports each bullet under Revisions: that lacks the two-space indent.
// The test reads the line after only the // is stripped, so the spaces count.
//
// Revisions:
//   - 2026-10-21 16:35: initial creation
func _ReportIndent(
	pass *analysis.Pass,
	fn *ast.FuncDecl,
) {
	if fn.Doc == nil {
		return
	}

	seen := false

	for _, comment := range fn.Doc.List {
		line := strings.TrimPrefix(
			comment.Text,
			"//",
		)
		if strings.TrimSpace(line) == REVISIONS {
			seen = true

			continue
		}

		if !seen || !DASH_FORM.MatchString(line) || INDENT_FORM.MatchString(line) {
			continue
		}

		_Fail(
			pass,
			fn.Name.Pos(),
			BAD_INDENT,
			FIX_INDENT,
		)
	}
}
