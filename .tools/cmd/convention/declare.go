package main

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
)

const (
	MIN_DECLARE_RUN = 2
)

// DECLARE reports a run of short declarations.
// Two or more := in a row belong in one var block.
// A lone := stays as it is.
var (
	DECLARE = _New(
		"declare",
		"declare reports short declarations that belong in a var block",
		_RunDeclare,
	)
)

// _RunDeclare reports each run of short declarations in a block, a case, or a select.
// A comment or a blank line is not a statement, so it does not end the run.
//
// Revisions:
//   - 2026-10-21 20:42: initial creation
func _RunDeclare(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_DeclareNode(
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

// _DeclareNode reads the statement list of one block, one case, or one select arm.
//
// Revisions:
//   - 2026-10-21 20:42: initial creation
func _DeclareNode(
	pass *analysis.Pass,
	node ast.Node,
) {
	switch typed := node.(type) {
	case *ast.BlockStmt:
		_DeclareList(
			pass,
			typed.List,
		)
	case *ast.CaseClause:
		_DeclareList(
			pass,
			typed.Body,
		)
	case *ast.CommClause:
		_DeclareList(
			pass,
			typed.Body,
		)
	}
}

// _DeclareList reports the second := of a run, and each := after that.
// Any other statement ends the run.
//
// Revisions:
//   - 2026-10-21 20:42: initial creation
func _DeclareList(
	pass *analysis.Pass,
	list []ast.Stmt,
) {
	run := 0

	for _, stmt := range list {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE {
			run = 0

			continue
		}

		run++
		if run < MIN_DECLARE_RUN {
			continue
		}

		_Fail(
			pass,
			assign.Pos(),
			BAD_DECLARE,
			FIX_DECLARE,
		)
	}
}
