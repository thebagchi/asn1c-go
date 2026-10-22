package main

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
)

// SNAKE reports a const or a package-level var that is not CAPITAL_SNAKE.
var (
	SNAKE = _New(
		"snake",
		"snake reports a const or a package-level var that is not CAPITAL_SNAKE",
		_RunSnake,
	)
)

// _RunSnake reports each const and package-level var that breaks the spelling rule.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _RunSnake(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			top := map[*ast.GenDecl]bool{}

			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if ok {
					top[gen] = true
				}
			}

			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_SnakeNode(
						pass,
						top,
						node,
					)

					return true
				},
			)
		},
	)

	return nil, nil
}

// _SnakeNode reports one declaration when it is a const or a package-level var.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _SnakeNode(
	pass *analysis.Pass,
	top map[*ast.GenDecl]bool,
	node ast.Node,
) {
	gen, ok := node.(*ast.GenDecl)
	if !ok {
		return
	}

	if gen.Tok == token.CONST || (gen.Tok == token.VAR && top[gen]) {
		_SnakeDecl(
			pass,
			gen,
		)
	}
}

// _SnakeDecl reports each name in one const or var block.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _SnakeDecl(
	pass *analysis.Pass,
	gen *ast.GenDecl,
) {
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}

		for _, name := range value.Names {
			_SnakeName(
				pass,
				name,
			)
		}
	}
}

// _SnakeName reports one ident that is not CAPITAL_SNAKE and not an allowed exception.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 01:38: report an error line with the rule and the fix
//   - 2026-10-04 11:12: state the spelling rule, and do not suggest a name
func _SnakeName(
	pass *analysis.Pass,
	name *ast.Ident,
) {
	if name == nil || name.Name == "_" || name.Name == "Analyzer" {
		return
	}

	if ERR_FORM.MatchString(
		name.Name,
	) {
		return
	}

	if SNAKE_FORM.MatchString(
		name.Name,
	) {
		return
	}

	_Fail(
		pass,
		name.Pos(),
		BAD_SNAKE,
		FIX_SNAKE,
	)
}
