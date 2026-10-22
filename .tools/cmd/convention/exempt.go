package main

import "go/ast"

// _ValueExempt reports whether decl is a method the standard library calls on a value.
// A pointer receiver on String drops a value from fmt.Stringer.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _ValueExempt(decl *ast.FuncDecl) bool {
	if decl == nil || decl.Name == nil || decl.Type == nil {
		return false
	}

	switch decl.Name.Name {
	case "String", "Error":
		return _NoParams(
			decl.Type,
		) && _OneIdent(
			decl.Type.Results,
			"string",
		)
	case "Len":
		return _NoParams(
			decl.Type,
		) && _OneIdent(
			decl.Type.Results,
			"int",
		)
	case "Less":
		return _TwoIdents(
			decl.Type.Params,
			"int",
		) && _OneIdent(
			decl.Type.Results,
			"bool",
		)
	case "Swap":
		return _TwoIdents(
			decl.Type.Params,
			"int",
		) && _NoResults(
			decl.Type,
		)
	case "MarshalJSON", "MarshalText":
		return _NoParams(
			decl.Type,
		) && _BytesError(
			decl.Type.Results,
		)
	default:
		return false
	}
}

// _NoParams reports whether kind has no parameters.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _NoParams(kind *ast.FuncType) bool {
	return _ParamCount(
		kind.Params,
	) == 0
}

// _NoResults reports whether kind has no results.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _NoResults(kind *ast.FuncType) bool {
	return _ParamCount(
		kind.Results,
	) == 0
}

// _ParamCount counts parameters, and counts a, b int as two.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _ParamCount(list *ast.FieldList) int {
	if list == nil {
		return 0
	}

	count := 0

	for _, field := range list.List {
		count += _NameCount(
			field,
		)
	}

	return count
}

// _NameCount returns the number of names in field, or one when the type is unnamed.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _NameCount(field *ast.Field) int {
	n := len(
		field.Names,
	)
	if n == 0 {
		return 1
	}

	return n
}

// _OneIdent reports whether list is one value of the named type.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _OneIdent(
	list *ast.FieldList,
	name string,
) bool {
	if _ParamCount(
		list,
	) != 1 {
		return false
	}

	return _Ident(
		list.List[0].Type,
		name,
	)
}

// _TwoIdents reports whether list is two values of the named type.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _TwoIdents(
	list *ast.FieldList,
	name string,
) bool {
	if !_Pair(
		_ParamCount(
			list,
		),
	) {
		return false
	}

	for _, field := range list.List {
		if !_Ident(
			field.Type,
			name,
		) {
			return false
		}
	}

	return true
}

// _BytesError reports whether list is []byte and error.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _BytesError(list *ast.FieldList) bool {
	if list == nil || !_Pair(
		len(
			list.List,
		),
	) {
		return false
	}

	if !_ByteSlice(
		list.List[0].Type,
	) {
		return false
	}

	return _Ident(
		list.List[1].Type,
		"error",
	)
}

// _ByteSlice reports whether expr is a slice of byte.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _ByteSlice(expr ast.Expr) bool {
	array, ok := _Bare(
		expr,
	).(*ast.ArrayType)
	if !ok || array.Len != nil {
		return false
	}

	return _Ident(
		array.Elt,
		"byte",
	)
}

// _Ident reports whether expr is the named identifier.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Ident(
	expr ast.Expr,
	name string,
) bool {
	ident, ok := _Bare(
		expr,
	).(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == name
}

// PAIR is two parameters or two results.
const (
	PAIR = 2
)

// _Pair reports whether count is two.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Pair(count int) bool {
	return count == PAIR
}

// _Bare removes parentheses around expr.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Bare(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}

		expr = paren.X
	}
}
