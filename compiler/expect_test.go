package compiler

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/thebagchi/asn1c-go/ast"
)

// How an expectation is printed when it does not match. Indented, because a
// node that disagrees somewhere deep is unreadable on one line.
const (
	EXPECT_INDENT = "  "
)

// _Want compares what the parser built against an expectation written in the
// schema's own JSON.
//
// The expectation is JSON rather than a Go literal because a oneof nests: a
// component named "age" of type INTEGER is five Go composite literals and
// one line of this, and the Go version does not fit the column limit at the
// depth these tests reach.
//
// It is not a weaker check for being shorter. protojson refuses a field the
// schema does not declare, so a mistyped expectation fails where a map key
// would once have matched nothing; and the comparison is proto.Equal, which
// is what a generated message must be compared with - reflect.DeepEqual
// reads the internal state every message carries and can call two equal
// messages different.
//
// Revisions:
//   - 2026-09-26 04:12: initial creation
func _Want(t *testing.T, got proto.Message, want string) {
	t.Helper()

	expected := got.ProtoReflect().New().Interface()
	if err := protojson.Unmarshal([]byte(want), expected); err != nil {
		t.Fatalf("the expectation is not a %T: %v", got, err)
	}

	if proto.Equal(got, expected) {
		return
	}

	t.Errorf("got\n%s\nwant\n%s", _JSON(got), _JSON(expected))
}

// _JSON renders a node the way an expectation is written, so that what a
// failure prints can be pasted back into the test once it is understood.
//
// Revisions:
//   - 2026-09-26 04:12: initial creation
func _JSON(node proto.Message) string {
	marshal := protojson.MarshalOptions{Multiline: true, Indent: EXPECT_INDENT}

	data, err := marshal.Marshal(node)
	if err != nil {
		return err.Error()
	}

	return string(data)
}

// _Parse parses one module and returns it, failing the test if it does not
// parse.
//
// Revisions:
//   - 2026-09-26 04:12: initial creation
func _Parse(t *testing.T, source string) *ast.Module {
	t.Helper()

	modules, err := ParseModules([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(modules))
	}

	return modules[0]
}

// _ParseType parses a module holding one type assignment and returns the
// type it assigns.
//
// Revisions:
//   - 2026-09-26 04:12: initial creation
func _ParseType(t *testing.T, body string) *ast.Type {
	t.Helper()

	module := _Parse(t, "Sample DEFINITIONS ::= BEGIN "+body+" END")

	assignments := module.GetAssignments()
	if len(assignments) != 1 {
		t.Fatalf("got %d assignments, want 1", len(assignments))
	}

	return assignments[0].GetType()
}

// _ParseAssignment parses a module holding one assignment and returns it.
//
// Revisions:
//   - 2026-09-26 04:12: initial creation
func _ParseAssignment(t *testing.T, body string) *ast.Assignment {
	t.Helper()

	module := _Parse(t, "Sample DEFINITIONS ::= BEGIN "+body+" END")

	assignments := module.GetAssignments()
	if len(assignments) != 1 {
		t.Fatalf("got %d assignments, want 1", len(assignments))
	}

	return assignments[0]
}

// _Quoted renders a string as the JSON one an expectation is written with,
// which the XML cases need: an element is full of quotes and angle brackets
// and writing it out by hand twice invites a typo that looks like a failure.
//
// Revisions:
//   - 2026-09-26 04:38: initial creation
func _Quoted(text string) string {
	data, err := json.Marshal(text)
	if err != nil {
		return `""`
	}

	return string(data)
}
