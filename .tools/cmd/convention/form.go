package main

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
)

// _Form holds the report text for one layout rule.
// single is set when one item must use the layout form.
// A call and a signature leave single unset, so one item stays on one line.
type _Form struct {
	single    bool
	open      string
	shared    string
	close     string
	openFix   string
	sharedFix string
	closeFix  string
}

// _Span is one opening token, the items inside it, and the closing token.
type _Span struct {
	open   token.Pos
	close  token.Pos
	starts []token.Pos
	end    token.Pos
}

// _Layout reports an opening, a shared line, or a closing token that breaks the form.
// An empty list stays on one line.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Layout(
	pass *analysis.Pass,
	form *_Form,
	span *_Span,
) {
	if !_Apply(
		form,
		span,
	) {
		return
	}

	_OpenItem(
		pass,
		form,
		span,
	)
	_SharedItems(
		pass,
		form,
		span,
	)
	_CloseItem(
		pass,
		form,
		span,
	)
}

// _Apply reports whether this list is large enough for the layout form.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Apply(
	form *_Form,
	span *_Span,
) bool {
	count := len(
		span.starts,
	)
	if count == 0 {
		return false
	}

	if count == 1 && !form.single {
		return false
	}

	return true
}

// _OpenItem reports a first item that shares a line with the opening token.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _OpenItem(
	pass *analysis.Pass,
	form *_Form,
	span *_Span,
) {
	if _Line(
		pass,
		span.open,
	) != _Line(
		pass,
		span.starts[0],
	) {
		return
	}

	_Fail(
		pass,
		span.open,
		form.open,
		form.openFix,
	)
}

// _SharedItems reports each item that shares a line with the item before it.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _SharedItems(
	pass *analysis.Pass,
	form *_Form,
	span *_Span,
) {
	count := len(
		span.starts,
	)

	for index := 1; index < count; index++ {
		if _Line(
			pass,
			span.starts[index],
		) != _Line(
			pass,
			span.starts[index-1],
		) {
			continue
		}

		_Fail(
			pass,
			span.starts[index],
			form.shared,
			form.sharedFix,
		)
	}
}

// _CloseItem reports a last item that shares a line with the closing token.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _CloseItem(
	pass *analysis.Pass,
	form *_Form,
	span *_Span,
) {
	if _Line(
		pass,
		span.end,
	) != _Line(
		pass,
		span.close,
	) {
		return
	}

	_Fail(
		pass,
		span.close,
		form.close,
		form.closeFix,
	)
}

// _Line returns the source line of pos, or 0 when pos is not valid.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Line(
	pass *analysis.Pass,
	pos token.Pos,
) int {
	if !pos.IsValid() {
		return 0
	}

	return pass.Fset.Position(
		pos,
	).Line
}

// _ExprStarts returns the start of each expression.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _ExprStarts(exprs []ast.Expr) []token.Pos {
	var starts []token.Pos

	for _, expr := range exprs {
		starts = append(
			starts,
			expr.Pos(),
		)
	}

	return starts
}

// _LastExpr returns the end of the last expression.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _LastExpr(exprs []ast.Expr) token.Pos {
	count := len(
		exprs,
	)
	if count == 0 {
		return token.NoPos
	}

	return exprs[count-1].End()
}

// _FieldStarts returns the start of each parameter name, or of the type when the name is absent.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _FieldStarts(list *ast.FieldList) []token.Pos {
	if list == nil {
		return nil
	}

	var starts []token.Pos

	for _, field := range list.List {
		starts = _FieldPos(
			starts,
			field,
		)
	}

	return starts
}

// _FieldPos appends one position for each name in field.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _FieldPos(
	starts []token.Pos,
	field *ast.Field,
) []token.Pos {
	if len(
		field.Names,
	) == 0 {
		return append(
			starts,
			field.Type.Pos(),
		)
	}

	for _, name := range field.Names {
		starts = append(
			starts,
			name.Pos(),
		)
	}

	return starts
}

// _LastField returns the end of the last field.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _LastField(list *ast.FieldList) token.Pos {
	if list == nil || len(
		list.List,
	) == 0 {
		return token.NoPos
	}

	last := len(
		list.List,
	) - 1

	return list.List[last].End()
}
