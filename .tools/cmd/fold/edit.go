package main

import (
	"go/ast"
	"go/scanner"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// MIN_ITEMS is the item count at which a list takes the layout form.
const (
	MIN_ITEMS = 2
)

// _Edit is one insertion of text at a byte offset.
type _Edit struct {
	at   int
	text string
}

// _Span is one opening token, the items inside it, and the closing token.
type _Span struct {
	open   token.Pos
	close  token.Pos
	starts []token.Pos
	end    token.Pos
}

// _Edits returns the insertions that fold every call, signature and struct literal of file.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Edits(
	pkg *packages.Package,
	file *ast.File,
	src []byte,
) []*_Edit {
	var edits []*_Edit

	ast.Inspect(
		file,
		func(node ast.Node) bool {
			span := _Target(
				pkg,
				node,
			)
			if span != nil {
				edits = append(
					edits,
					_SpanEdits(
						pkg.Fset,
						src,
						span,
					)...,
				)
			}

			return true
		},
	)

	return edits
}

// _Target returns the span of node when the layout form applies to it, or nil.
// The form starts at two arguments, two parameters or one struct field.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Target(
	pkg *packages.Package,
	node ast.Node,
) *_Span {
	switch typed := node.(type) {
	case *ast.CallExpr:
		return _CallTarget(
			pkg,
			typed,
		)
	case *ast.FuncType:
		return _Many(
			_SignSpan(
				typed.Params,
			),
		)
	case *ast.CompositeLit:
		return _LitTarget(
			pkg,
			typed,
		)
	}

	return nil
}

// _Many returns span when it holds two items or more.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Many(span *_Span) *_Span {
	if span == nil || len(
		span.starts,
	) < MIN_ITEMS {
		return nil
	}

	return span
}

// _CallTarget returns the span of a call with two arguments or more.
// A conversion is a type, not a call, so it gives nil.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _CallTarget(
	pkg *packages.Package,
	call *ast.CallExpr,
) *_Span {
	if len(
		call.Args,
	) < MIN_ITEMS {
		return nil
	}

	tv, ok := pkg.TypesInfo.Types[call.Fun]
	if ok && tv.IsType() {
		return nil
	}

	return &_Span{
		open:   call.Lparen,
		close:  call.Rparen,
		starts: _ExprStarts(call.Args),
		end:    call.Args[len(call.Args)-1].End(),
	}
}

// _LitTarget returns the span of a struct literal with one element or more.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _LitTarget(
	pkg *packages.Package,
	lit *ast.CompositeLit,
) *_Span {
	if len(
		lit.Elts,
	) == 0 {
		return nil
	}

	typed := pkg.TypesInfo.TypeOf(
		lit,
	)
	if typed == nil || !_IsStruct(
		types.Unalias(
			typed,
		),
	) {
		return nil
	}

	return &_Span{
		open:   lit.Lbrace,
		close:  lit.Rbrace,
		starts: _ExprStarts(lit.Elts),
		end:    lit.Elts[len(lit.Elts)-1].End(),
	}
}

// _IsStruct reports whether typed is a struct or a pointer to a struct.
// The pointer case is an elided literal written where &T{...} was meant.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _IsStruct(typed types.Type) bool {
	var (
		under       = typed.Underlying()
		pointer, ok = under.(*types.Pointer)
	)
	if ok {
		under = types.Unalias(
			pointer.Elem(),
		).Underlying()
	}

	_, ok = under.(*types.Struct)

	return ok
}

// _ExprStarts returns the start of each expression.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _ExprStarts(exprs []ast.Expr) []token.Pos {
	starts := make(
		[]token.Pos,
		0,
		len(exprs),
	)

	for _, expr := range exprs {
		starts = append(
			starts,
			expr.Pos(),
		)
	}

	return starts
}

// _SignSpan reads the parentheses and the parameters of one list.
// It gives nil for a list that is absent.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _SignSpan(list *ast.FieldList) *_Span {
	if list == nil || !list.Opening.IsValid() || len(
		list.List,
	) == 0 {
		return nil
	}

	span := &_Span{
		open:  list.Opening,
		close: list.Closing,
		end:   list.List[len(list.List)-1].End(),
	}

	for _, field := range list.List {
		span.starts = _FieldStarts(
			span.starts,
			field,
		)
	}

	return span
}

// _FieldStarts appends one start for each name of field, or one for its type.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _FieldStarts(
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

// _SpanEdits returns the insertions that put each item of span on a line of its own.
// A newline goes before the first item when it shares the opener's line.
// A newline goes before each item that shares a line with the item before it.
// A newline, and a comma when it is absent, go before a closer on the last item's line.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _SpanEdits(
	fset *token.FileSet,
	src []byte,
	span *_Span,
) []*_Edit {
	var edits []*_Edit

	var (
		line = func(pos token.Pos) int {
			return fset.Position(pos).Line
		}
		offset = func(pos token.Pos) int {
			return fset.Position(pos).Offset
		}
	)

	if line(span.open) == line(span.starts[0]) {
		edits = append(
			edits,
			&_Edit{
				at:   offset(span.starts[0]),
				text: "\n",
			},
		)
	}

	for index := 1; index < len(span.starts); index++ {
		if line(span.starts[index]) == line(span.starts[index-1]) {
			edits = append(
				edits,
				&_Edit{
					at:   offset(span.starts[index]),
					text: "\n",
				},
			)
		}
	}

	if line(span.end) != line(span.close) {
		return edits
	}

	return append(
		edits,
		_CloseEdit(
			src,
			offset(span.end),
			offset(span.close),
		),
	)
}

// _CloseEdit returns the insertion before a closer.
// It adds the comma when no comma follows the last item.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _CloseEdit(
	src []byte,
	from int,
	to int,
) *_Edit {
	if _HasComma(
		src[from:to],
	) {
		return &_Edit{
			at:   to,
			text: "\n",
		}
	}

	return &_Edit{
		at:   to,
		text: ",\n",
	}
}

// _HasComma reports whether the Go tokens of gap include a comma.
// Comments in gap are skipped.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _HasComma(gap []byte) bool {
	var scan scanner.Scanner

	file := token.NewFileSet().AddFile(
		"",
		-1,
		len(gap),
	)
	scan.Init(
		file,
		gap,
		nil,
		0,
	)

	for {
		_, tok, _ := scan.Scan()

		switch tok {
		case token.EOF:
			return false
		case token.COMMA:
			return true
		}
	}
}
