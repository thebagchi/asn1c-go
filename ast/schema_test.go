// The tests here guard the contract between proto/ast.proto and the grammar
// that fills it. The compiler builds a generic map in its rule actions and
// hands it to protojson, so what has to hold is that a map shaped the way an
// action shapes it becomes the node it was meant to be - and that one which
// could not have been written is refused.
package ast_test

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/thebagchi/asn1c-go/ast"
)

// MAP is what a grammar action builds, spelt the way grammar.y spells it.
type MAP = map[string]any

// LIST is a repeated field as an action builds it.
type LIST = []any

// _Module unmarshals one map through the path the compiler uses: encoding/json
// out of the generic map, protojson into the node.
//
// Revisions:
//   - 2026-09-26 01:02: initial creation
func _Module(t *testing.T, from MAP) *ast.Module {
	t.Helper()

	data, err := json.Marshal(from)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	module := &ast.Module{}
	if err := protojson.Unmarshal(data, module); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return module
}

// TestSchemaHeader checks SchemaHeader: the arcs of a module's object
// identifier, and that a number an action put in the map arrives as one.
// protojson writes an int64 as a string and reads either, which is the trap
// this is here for.
//
// Revisions:
//   - 2026-09-26 01:02: initial creation
func TestSchemaHeader(t *testing.T) {
	module := _Module(t, MAP{
		"moduleName": "Sample",
		"definitiveOid": LIST{
			MAP{"name": "iso", "number": 1},
			MAP{"number": 2},
		},
		"tagDefault": "AUTOMATIC",
	})

	if module.GetModuleName() != "Sample" {
		t.Errorf("got module %q, want Sample", module.GetModuleName())
	}

	arcs := module.GetDefinitiveOid()
	if len(arcs) != 2 {
		t.Fatalf("got %d arcs, want 2", len(arcs))
	}

	if arcs[0].GetNumber() != 1 {
		t.Errorf("got arc %d, want 1", arcs[0].GetNumber())
	}
}

// TestSchemaAssignmentArms checks SchemaAssignmentArms: an assignment's body
// is one of four things, and the map says which by the key it nests under.
//
// Revisions:
//   - 2026-09-26 01:02: initial creation
func TestSchemaAssignmentArms(t *testing.T) {
	typed := MAP{
		"name": "Age",
		"type": MAP{"builtin": MAP{"name": "INTEGER"}},
	}

	valued := MAP{
		"name": "someone",
		"value": MAP{
			"type":  MAP{"reference": MAP{"name": "Person"}},
			"value": MAP{"number": "42"},
		},
	}

	module := _Module(t, MAP{
		"moduleName":  "Sample",
		"assignments": LIST{typed, valued},
	})

	first := module.GetAssignments()[0]
	if _, ok := first.GetBody().(*ast.Assignment_Type); !ok {
		t.Fatalf("got body %T, want *ast.Assignment_Type", first.GetBody())
	}

	if _, ok := first.GetType().GetKind().(*ast.Type_Builtin); !ok {
		t.Errorf("got kind %T, want *ast.Type_Builtin", first.GetType().GetKind())
	}

	second := module.GetAssignments()[1]
	if _, ok := second.GetBody().(*ast.Assignment_Value); !ok {
		t.Fatalf("got body %T, want *ast.Assignment_Value", second.GetBody())
	}

	// An ASN.1 INTEGER has no bound, so a number is kept as the text a
	// module wrote rather than parsed into one here.
	if got := second.GetValue().GetValue().GetNumber(); got != "42" {
		t.Errorf("got number %q, want 42", got)
	}
}

// TestSchemaNamedNumber checks SchemaNamedNumber. A named number is written
// with a number or with the name of one defined elsewhere, and a number of
// zero is a value modules really do use - so "the number is zero" and "no
// number was written" must not be the same state.
//
// Revisions:
//   - 2026-09-26 01:02: initial creation
func TestSchemaNamedNumber(t *testing.T) {
	flags := MAP{
		"name": "Flags",
		"type": MAP{
			"builtin": MAP{
				"name": "INTEGER",
				"named": LIST{
					MAP{"name": "none", "number": 0},
					MAP{"name": "other", "reference": "elsewhere"},
				},
			},
		},
	}

	module := _Module(t, MAP{
		"moduleName":  "Sample",
		"assignments": LIST{flags},
	})

	named := module.GetAssignments()[0].GetType().GetBuiltin().GetNamed()
	if len(named) != 2 {
		t.Fatalf("got %d named numbers, want 2", len(named))
	}

	if _, ok := named[0].GetValue().(*ast.NamedNumber_Number); !ok {
		t.Errorf("a written zero lost its arm: %T", named[0].GetValue())
	}

	if _, ok := named[1].GetValue().(*ast.NamedNumber_Reference); !ok {
		t.Errorf("got %T, want *ast.NamedNumber_Reference", named[1].GetValue())
	}
}

// TestSchemaRejectsTwoArms checks SchemaRejectsTwoArms. This is what the
// oneof is for: a node that could not have been written is refused where it
// is built, rather than reaching a later pass as something silently wrong.
//
// Revisions:
//   - 2026-09-26 01:02: initial creation
func TestSchemaRejectsTwoArms(t *testing.T) {
	cases := []struct {
		name string
		from MAP
	}{
		{
			name: "built-in and referenced at once",
			from: MAP{
				"builtin":   MAP{"name": "INTEGER"},
				"reference": MAP{"name": "Foo"},
			},
		},
		{
			name: "referenced and selected at once",
			from: MAP{
				"reference": MAP{"name": "Foo"},
				"selection": MAP{"name": "alt"},
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			data, err := json.Marshal(item.from)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if err := protojson.Unmarshal(data, &ast.Type{}); err == nil {
				t.Error("two arms of the kind oneof were accepted")
			}
		})
	}
}
