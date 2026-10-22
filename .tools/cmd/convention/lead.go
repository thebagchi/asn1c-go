package main

import (
	"go/ast"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/analysis"
)

// LEAD reports an unexported function, method, or type with no leading _.
var (
	LEAD = _New(
		"lead",
		"lead reports an unexported function, method, or type with no leading _",
		_RunLead,
	)
)

// _RunLead reports each unexported name that breaks the leading-_ rule.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _RunLead(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					_LeadNode(
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

// _LeadNode reports one declaration when its name breaks the leading-_ rule.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _LeadNode(
	pass *analysis.Pass,
	node ast.Node,
) {
	switch decl := node.(type) {
	case *ast.FuncDecl:
		_LeadName(
			pass,
			decl.Name,
		)
	case *ast.TypeSpec:
		_LeadName(
			pass,
			decl.Name,
		)
		_LeadInterface(
			pass,
			decl,
		)
	}
}

// _LeadInterface reports an unexported method name on an interface.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _LeadInterface(
	pass *analysis.Pass,
	spec *ast.TypeSpec,
) {
	iface, ok := spec.Type.(*ast.InterfaceType)
	if !ok || iface.Methods == nil {
		return
	}

	for _, field := range iface.Methods.List {
		for _, name := range field.Names {
			_LeadName(
				pass,
				name,
			)
		}
	}
}

// _LeadName reports one ident when an unexported name breaks the leading-_ rule.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 01:38: report an error line with the rule and the fix
//   - 2026-10-04 11:12: state the spelling rule, and do not suggest a name
func _LeadName(
	pass *analysis.Pass,
	name *ast.Ident,
) {
	if name == nil || name.Name == "_" || ast.IsExported(
		name.Name,
	) || _Exempt(
		name.Name,
	) {
		return
	}

	if LEAD_FORM.MatchString(
		name.Name,
	) {
		return
	}

	_Fail(
		pass,
		name.Pos(),
		BAD_LEAD,
		FIX_LEAD,
	)
}

// _Exempt reports whether the toolchain fixes this name.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Exempt(name string) bool {
	switch name {
	case "main", "init", "TestMain":
		return true
	}

	if _Prefixed(
		name,
		"Test",
	) || _Prefixed(
		name,
		"Benchmark",
	) || _Prefixed(
		name,
		"Fuzz",
	) {
		return true
	}

	return _Example(
		name,
	)
}

// _Prefixed reports whether name is prefix plus an uppercase letter.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Prefixed(
	name string,
	prefix string,
) bool {
	rest, ok := strings.CutPrefix(
		name,
		prefix,
	)
	if !ok || rest == "" {
		return false
	}

	r, _ := utf8.DecodeRuneInString(
		rest,
	)

	return unicode.IsUpper(
		r,
	)
}

// _Example reports whether name is an Example function.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Example(name string) bool {
	if name == "Example" {
		return true
	}

	rest, ok := strings.CutPrefix(
		name,
		"Example",
	)
	if !ok || rest == "" {
		return false
	}

	r, _ := utf8.DecodeRuneInString(
		rest,
	)

	return r == '_' || unicode.IsUpper(
		r,
	)
}
