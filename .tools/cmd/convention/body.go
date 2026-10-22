package main

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

// BODY reports a function body, a closure body, or a deferred closure written on one line.
var (
	BODY = _New(
		"body",
		"body reports a function body or a deferred closure written on one line",
		_RunBody,
	)
)

// _RunBody reports each function body whose braces share a line.
// A deferred closure gets its own finding, because on one line it hides that it runs on return.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
func _RunBody(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_BodyNode(
						pass,
						node,
					)

					return true
				},
			)
		},
	)

	return nil, nil
}

// _BodyNode reports one function, one closure, or one deferred closure on one line.
// A FuncDecl with no body is an assembly stub and has no braces to read.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
func _BodyNode(
	pass *analysis.Pass,
	node ast.Node,
) {
	switch typed := node.(type) {
	case *ast.FuncDecl:
		if typed.Body == nil {
			return
		}

		_OneLine(
			pass,
			typed.Body,
			BAD_BODY,
			FIX_BODY,
		)
	case *ast.FuncLit:
		_OneLine(
			pass,
			typed.Body,
			BAD_BODY,
			FIX_BODY,
		)
	case *ast.DeferStmt:
		_DeferLine(
			pass,
			typed,
		)
	}
}

// _DeferLine reports a deferred closure whose body braces share a line.
// A deferred call of a named function is not a closure.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
func _DeferLine(
	pass *analysis.Pass,
	stmt *ast.DeferStmt,
) {
	closure, ok := ast.Unparen(
		stmt.Call.Fun,
	).(*ast.FuncLit)
	if !ok {
		return
	}

	_OneLine(
		pass,
		closure.Body,
		BAD_DEFER,
		FIX_DEFER,
	)
}

// _OneLine reports body when its opening and closing braces are on the same line.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
func _OneLine(
	pass *analysis.Pass,
	body *ast.BlockStmt,
	message string,
	fix string,
) {
	var (
		open = pass.Fset.Position(
			body.Lbrace,
		)
		end = pass.Fset.Position(
			body.Rbrace,
		)
	)
	if open.Line != end.Line {
		return
	}

	_Fail(
		pass,
		body.Lbrace,
		message,
		fix,
	)
}
