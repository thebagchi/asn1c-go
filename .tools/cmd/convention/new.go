package main

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

// _New builds an analyser with the shared module flag.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _New(
	name string,
	doc string,
	run func(*analysis.Pass) (any, error),
) *analysis.Analyzer {
	analyzer := &analysis.Analyzer{
		Name: name,
		Doc:  doc,
		Run:  run,
	}
	analyzer.Flags.String(
		"module",
		"",
		"module path",
	)

	return analyzer
}

// _Each visits each hand-written file in the package.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Each(
	pass *analysis.Pass,
	visit func(*ast.File),
) {
	for _, file := range pass.Files {
		if !common.Written(
			file,
		) {
			continue
		}

		visit(
			file,
		)
	}
}
