// This test is external: it reaches the resolver through its exported
// surface only, as an ordinary caller would.
package compiler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thebagchi/asn1c-go/ast"
	"github.com/thebagchi/asn1c-go/compiler"
)

// TestResolveObjects reads every information object the 3GPP specifications
// write in a class's own syntax.
//
// This is the pass the parser hands its work to. X.681 lets a class declare
// the notation its objects are written in, so the same braces hold a
// different language per class and no grammar covers them all - the parser
// keeps the text instead, and this walks it against the class's syntax list
// (lib/review.md 11.14 and 11.16).
//
// Every object in the corpus must resolve. An object that does not is
// either a class this misreads or a syntax list it does not follow, and
// both are defects rather than gaps: the text is all there.
//
// Revisions:
//   - 2026-09-24 22:41: initial creation
func TestResolveObjects(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "3gpp", "*.asn1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("no specifications to resolve")
	}

	objects := 0

	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		name := filepath.Base(path)

		modules, err := compiler.ParseModules(source)
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		registry := compiler.NewRegistry(modules)
		for _, err := range registry.Resolve(modules) {
			t.Errorf("%s: %v", name, err)
		}

		objects += _Resolved(modules)
	}

	// The radio resource specifications define no classes, so the whole of
	// this count comes from the application protocols.
	if objects < 7396 {
		t.Errorf("resolved %d objects, want at least 7396", objects)
	}
}

// _Resolved counts the objects a resolution read, which are the values that
// were opaque before it ran and carry their fields after.
//
// Revisions:
//   - 2026-09-24 22:41: initial creation
func _Resolved(modules []*ast.Module) int {
	resolved := 0

	value := func(subject *ast.Value) {
		if subject.GetObject() == nil {
			return
		}

		resolved++
	}

	// An element set holds an object set's objects, and nests wherever the
	// set was written as a union, so this one has to name itself.
	var set func(*ast.ElementSet)

	set = func(subject *ast.ElementSet) {
		if subject == nil {
			return
		}

		value(subject.GetValue())
		set(subject.GetAll())

		for _, operands := range []*ast.Operands{
			subject.GetUnion(),
			subject.GetIntersection(),
			subject.GetExcept(),
		} {
			for _, operand := range operands.GetOperands() {
				set(operand)
			}
		}
	}

	for _, module := range modules {
		for _, assignment := range module.GetAssignments() {
			value(assignment.GetValue().GetValue())

			if node := assignment.GetValueSet().GetSet(); node != nil {
				set(node.GetRoot())
				set(node.GetAdditional())
			}
		}
	}

	return resolved
}
