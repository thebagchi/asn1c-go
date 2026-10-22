package main

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// POINTER reports a parameter, result, field, or receiver that holds one of our structs by value.
var (
	POINTER = _New(
		"pointer",
		"pointer reports a value use of a struct this module declares",
		_RunPointer,
	)
)

// _RunPointer reports each value use of a struct this module declares.
// A receiver uses the same rule, except a method the standard library calls on a value.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 11:12: report a value receiver, except the seven standard-library methods
func _RunPointer(pass *analysis.Pass) (any, error) {
	module, err := _Module(
		pass,
	)
	if err != nil {
		return nil, err
	}

	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_PointerNode(
						pass,
						node,
						module,
					)

					return true
				},
			)
		},
	)

	return nil, nil
}

// _PointerNode reports value uses in one receiver, one function type, or one struct.
// A FuncDecl gives only its receiver, because ast.Inspect visits its FuncType next.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
//   - 2026-10-21 15:34: read every function type, so a closure, an interface method,
//     a named function type, and a function variable are reported
func _PointerNode(
	pass *analysis.Pass,
	node ast.Node,
	module string,
) {
	switch decl := node.(type) {
	case *ast.FuncDecl:
		_PointerRecv(
			pass,
			decl,
			module,
		)
	case *ast.FuncType:
		_WalkList(
			pass,
			decl.Params,
			module,
		)
		_WalkList(
			pass,
			decl.Results,
			module,
		)
	case *ast.StructType:
		_WalkStruct(
			pass,
			decl,
			module,
		)
	}
}

// _PointerRecv reports a value receiver.
// The seven methods the standard library calls on a value keep theirs.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
//   - 2026-10-21 15:34: read only the receiver; the FuncType case reads the signature
func _PointerRecv(
	pass *analysis.Pass,
	decl *ast.FuncDecl,
	module string,
) {
	if _ValueExempt(
		decl,
	) {
		return
	}

	_WalkList(
		pass,
		decl.Recv,
		module,
	)
}

// _WalkStruct checks the named fields of one struct.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _WalkStruct(
	pass *analysis.Pass,
	form *ast.StructType,
	module string,
) {
	if form.Fields == nil {
		return
	}

	for _, field := range form.Fields.List {
		if len(
			field.Names,
		) == 0 {
			continue
		}

		_WalkExpr(
			pass,
			field.Type,
			module,
		)
	}
}

// _WalkList checks each type in a parameter or result list.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _WalkList(
	pass *analysis.Pass,
	list *ast.FieldList,
	module string,
) {
	if list == nil {
		return
	}

	for _, field := range list.List {
		_WalkExpr(
			pass,
			field.Type,
			module,
		)
	}
}

// _WalkExpr reports a struct value.
// A nested function type is left to ast.Inspect, which visits it on its own.
// A second walk here would report each site twice.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-21 15:34: leave a nested function type to ast.Inspect
func _WalkExpr(
	pass *analysis.Pass,
	expr ast.Expr,
	module string,
) {
	switch typed := expr.(type) {
	case *ast.ParenExpr:
		_WalkExpr(
			pass,
			typed.X,
			module,
		)
	case *ast.StarExpr:
		return
	case *ast.FuncType:
		return
	case *ast.StructType:
		return
	default:
		_ReportValue(
			pass,
			expr,
			module,
		)
	}
}

// _ReportValue reports expr when it is a struct this module declares, held by value.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 01:38: report an error line with the rule and the fix
func _ReportValue(
	pass *analysis.Pass,
	expr ast.Expr,
	module string,
) {
	var (
		typed = pass.TypesInfo.TypeOf(
			expr,
		)
		obj = _StructObject(
			typed,
		)
	)
	if obj == nil || !_Ours(
		obj,
		module,
	) {
		return
	}

	var (
		name    = obj.Name()
		message = "struct " + name + " this module declares must be a pointer"
		fix     = "change " + name + " to *" + name
	)
	_Fail(
		pass,
		expr.Pos(),
		message,
		fix,
	)
}

// _StructObject returns the type name when typed is a named struct.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _StructObject(typed types.Type) *types.TypeName {
	if typed == nil {
		return nil
	}

	named, ok := types.Unalias(
		typed,
	).(*types.Named)
	if !ok {
		return nil
	}

	if _, ok = named.Underlying().(*types.Struct); !ok {
		return nil
	}

	return named.Obj()
}

// _Ours reports whether obj is a type this module declares.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Ours(
	obj *types.TypeName,
	module string,
) bool {
	if obj.Pkg() == nil || module == "" {
		return false
	}

	path := obj.Pkg().Path()

	return path == module || strings.HasPrefix(
		path,
		module+"/",
	)
}
