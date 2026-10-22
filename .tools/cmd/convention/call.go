package main

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

// CALL reports a call or a signature that is not one item to a line.
var (
	CALL = _New(
		"call",
		"call reports a call or a signature with two or more items on one line",
		_RunCall,
	)
)

// _RunCall reports each call and each parameter list that breaks the layout form.
// The form starts at two arguments, or at two parameters.
// One argument, one parameter, and an empty () stay on one line.
// A conversion is a type, not a call, so this check skips it.
// A builtin is a call.
// A result list is not a parameter list.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _RunCall(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_CallNode(
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

// _CallNode reports one call or one signature.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _CallNode(
	pass *analysis.Pass,
	node ast.Node,
) {
	switch typed := node.(type) {
	case *ast.CallExpr:
		_OneCall(
			pass,
			typed,
		)
	case *ast.FuncType:
		_Signature(
			pass,
			typed,
		)
	}
}

// _OneCall reports one call that breaks the layout form.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _OneCall(
	pass *analysis.Pass,
	call *ast.CallExpr,
) {
	if _Convert(
		pass,
		call,
	) {
		return
	}

	_Layout(
		pass,
		_CallForm(),
		_CallSpan(
			call,
		),
	)
}

// _CallForm returns the report text for a call.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _CallForm() *_Form {
	return &_Form{
		open:      BAD_CALL_OPEN,
		shared:    BAD_CALL_SHARED,
		close:     BAD_CALL_CLOSE,
		openFix:   FIX_CALL_OPEN,
		sharedFix: FIX_CALL_SHARED,
		closeFix:  FIX_CALL_CLOSE,
	}
}

// _CallSpan reads the parentheses and the arguments of one call.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _CallSpan(call *ast.CallExpr) *_Span {
	return &_Span{
		open:  call.Lparen,
		close: call.Rparen,
		starts: _ExprStarts(
			call.Args,
		),
		end: _LastExpr(
			call.Args,
		),
	}
}

// _Convert reports whether call is a type conversion.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Convert(
	pass *analysis.Pass,
	call *ast.CallExpr,
) bool {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok {
		return false
	}

	return tv.IsType()
}

// _Signature reports one parameter list that breaks the layout form.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Signature(
	pass *analysis.Pass,
	kind *ast.FuncType,
) {
	_Layout(
		pass,
		_SignForm(),
		_SignSpan(
			kind.Params,
		),
	)
}

// _SignForm returns the report text for a parameter list.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _SignForm() *_Form {
	return &_Form{
		open:      BAD_SIGN_OPEN,
		shared:    BAD_SIGN_SHARED,
		close:     BAD_SIGN_CLOSE,
		openFix:   FIX_SIGN_OPEN,
		sharedFix: FIX_SIGN_SHARED,
		closeFix:  FIX_SIGN_CLOSE,
	}
}

// _SignSpan reads the parentheses and the parameters of one list.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _SignSpan(list *ast.FieldList) *_Span {
	span := &_Span{
		starts: _FieldStarts(
			list,
		),
		end: _LastField(
			list,
		),
	}

	if list == nil {
		return span
	}

	span.open = list.Opening
	span.close = list.Closing

	return span
}
