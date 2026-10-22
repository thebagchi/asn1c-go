package main

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

// FIELDS reports a struct whose fields are split by a blank line or a comment.
var (
	FIELDS = _New(
		"fields",
		"fields reports a struct whose fields are split by a blank line or a comment",
		_RunFields,
	)
)

// _RunFields reports each struct whose fields are not one contiguous block.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _RunFields(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					form, ok := node.(*ast.StructType)
					if ok {
						_Fields(
							pass,
							form,
						)
					}

					return true
				},
			)
		},
	)

	return nil, nil
}

// _Fields reports the second field of each pair that is not on the next line.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 01:38: report an error line with the rule and the fix
func _Fields(
	pass *analysis.Pass,
	form *ast.StructType,
) {
	if form.Fields == nil {
		return
	}

	list := form.Fields.List

	for i := range list {
		if i == 0 {
			continue
		}

		var (
			end = pass.Fset.Position(
				list[i-1].End(),
			)
			next = pass.Fset.Position(
				list[i].Pos(),
			)
		)
		if next.Line > end.Line+1 {
			_Fail(
				pass,
				list[i].Pos(),
				BAD_FIELDS,
				FIX_FIELDS,
			)
		}
	}
}
