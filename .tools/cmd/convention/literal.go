package main

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// LITERAL reports a struct literal that is not one field to a line.
var (
	LITERAL = _New(
		"literal",
		"literal reports a struct literal that is not one field to a line",
		_RunLiteral,
	)
)

// _RunLiteral reports each struct literal that breaks the layout form.
// An empty literal stays {}.
// An elided literal inside a literal of pointers is a struct literal.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _RunLiteral(pass *analysis.Pass) (any, error) {
	form := _LiteralForm()

	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_LiteralNode(
						pass,
						form,
						node,
					)

					return true
				},
			)
		},
	)

	return nil, nil
}

// _LiteralForm returns the report text for a struct literal.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _LiteralForm() *_Form {
	return &_Form{
		single:    true,
		open:      BAD_OPEN,
		shared:    BAD_SHARED,
		close:     BAD_CLOSE,
		openFix:   FIX_OPEN,
		sharedFix: FIX_SHARED,
		closeFix:  FIX_CLOSE,
	}
}

// _LiteralNode reports one composite literal when it is a struct literal.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _LiteralNode(
	pass *analysis.Pass,
	form *_Form,
	node ast.Node,
) {
	lit, ok := node.(*ast.CompositeLit)
	if !ok {
		return
	}

	if !_StructLit(
		pass,
		lit,
	) {
		return
	}

	_Layout(
		pass,
		form,
		_LitSpan(
			lit,
		),
	)
}

// _LitSpan reads the brace and the fields of one literal.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _LitSpan(lit *ast.CompositeLit) *_Span {
	return &_Span{
		open:  lit.Lbrace,
		close: lit.Rbrace,
		starts: _ExprStarts(
			lit.Elts,
		),
		end: _LastExpr(
			lit.Elts,
		),
	}
}

// _StructLit reports whether lit is a struct literal, including an elided one.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _StructLit(
	pass *analysis.Pass,
	lit *ast.CompositeLit,
) bool {
	typed := pass.TypesInfo.TypeOf(
		lit,
	)
	if typed == nil {
		return false
	}

	return _IsStruct(
		typed,
	)
}

// _IsStruct reports whether typed is a struct or a pointer to a struct.
// The pointer case is an elided literal written where &T{...} was meant.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _IsStruct(typed types.Type) bool {
	base := types.Unalias(
		typed,
	)
	if _AsStruct(
		base,
	) {
		return true
	}

	return _PointsAtStruct(
		base,
	)
}

// _AsStruct reports whether typed's underlying type is a struct.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _AsStruct(typed types.Type) bool {
	_, ok := typed.Underlying().(*types.Struct)

	return ok
}

// _PointsAtStruct reports whether typed is a pointer to a struct.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _PointsAtStruct(typed types.Type) bool {
	pointer, ok := typed.Underlying().(*types.Pointer)
	if !ok {
		return false
	}

	return _AsStruct(
		types.Unalias(
			pointer.Elem(),
		),
	)
}
