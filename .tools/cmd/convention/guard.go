package main

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// GUARD reports a struct whose mutex is not above the data it guards.
var (
	GUARD = _New(
		"guard",
		"guard reports a lock that has data above it",
		_RunGuard,
	)
)

// _RunGuard reports each struct with a lock below some of its data.
// The name is not mutex, because the rule name and the message share the line.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
func _RunGuard(pass *analysis.Pass) (any, error) {
	_Each(
		pass,
		func(file *ast.File) {
			ast.Inspect(
				file,
				func(node ast.Node) bool {
					form, ok := node.(*ast.StructType)
					if ok {
						_Guard(
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

// _Guard reports each lock that has data above it.
// A lock guards the fields below it, so data above a lock is data that it does not guard.
// A leading run of locks, then the data, stays quiet.
// A struct whose only field is a lock has nothing above it.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
//   - 2026-10-21 16:15: report a lock with data above it, not only a last lock
func _Guard(
	pass *analysis.Pass,
	form *ast.StructType,
) {
	if form.Fields == nil {
		return
	}

	data := false

	for _, field := range form.Fields.List {
		lock := _Lock(
			pass.TypesInfo.TypeOf(
				field.Type,
			),
		)
		if !lock {
			data = true

			continue
		}

		if data {
			_Fail(
				pass,
				field.Pos(),
				BAD_GUARD,
				FIX_GUARD,
			)
		}
	}
}

// _Lock reports whether typed is sync.Mutex or sync.RWMutex.
//
// Revisions:
//   - 2026-10-21 15:34: initial creation
func _Lock(typed types.Type) bool {
	if typed == nil {
		return false
	}

	named, ok := types.Unalias(
		typed,
	).(*types.Named)
	if !ok {
		return false
	}

	obj := named.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != "sync" {
		return false
	}

	return obj.Name() == "Mutex" || obj.Name() == "RWMutex"
}
