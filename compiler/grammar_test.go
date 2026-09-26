// The tests here are in the package rather than beside it, because the grammar
// under test is generated
// and goyacc generates that type unexported. go.md permits the internal form
// when the thing under test cannot be named from outside, and asks that the
// file say why; this is that.
package compiler

import (
	"testing"

	"github.com/thebagchi/asn1c-go/ast"
)

// TestParseModuleHeader checks that each optional clause of the X.680
// ModuleDefinition header - the definitive object identifier and its IRI,
// the encoding reference, the tag default and the extension default - is
// recognized on its own and alongside the others, since each one is
// separately omittable and it is the combination that the grammar has to
// keep unambiguous.
//
// Revisions:
//   - 2026-09-24 09:41: initial creation
func TestParseModuleHeader(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "definitive oid",
			source: "Sample { iso(1) member-body(2) example 42 } " +
				"DEFINITIONS ::= BEGIN END",
			want: `{"moduleName":"Sample","definitiveOid":[
				{"name":"iso","number":"1"},
				{"name":"member-body","number":"2"},
				{"name":"example"},
				{"number":"42"}]}`,
		},
		{
			name:   "definitive oid and iri",
			source: `Sample { iso(1) } "/ISO/Example" DEFINITIONS ::= BEGIN END`,
			want: `{"moduleName":"Sample",
				"definitiveOid":[{"name":"iso","number":"1"}],
				"iri":"\"/ISO/Example\""}`,
		},
		{
			name:   "encoding reference",
			source: "Sample DEFINITIONS XER INSTRUCTIONS ::= BEGIN END",
			want:   `{"moduleName":"Sample","encodingReference":"XER"}`,
		},
		{
			name:   "explicit tags",
			source: "Sample DEFINITIONS EXPLICIT TAGS ::= BEGIN END",
			want:   `{"moduleName":"Sample","tagDefault":"EXPLICIT"}`,
		},
		{
			name:   "implicit tags",
			source: "Sample DEFINITIONS IMPLICIT TAGS ::= BEGIN END",
			want:   `{"moduleName":"Sample","tagDefault":"IMPLICIT"}`,
		},
		{
			name:   "automatic tags",
			source: "Sample DEFINITIONS AUTOMATIC TAGS ::= BEGIN END",
			want:   `{"moduleName":"Sample","tagDefault":"AUTOMATIC"}`,
		},
		{
			name:   "extensibility implied",
			source: "Sample DEFINITIONS EXTENSIBILITY IMPLIED ::= BEGIN END",
			want:   `{"moduleName":"Sample","extensibility":true}`,
		},
		{
			name: "every clause at once",
			source: `Sample { iso(1) } "/ISO" DEFINITIONS XER INSTRUCTIONS ` +
				"AUTOMATIC TAGS EXTENSIBILITY IMPLIED ::= BEGIN END",
			want: `{"moduleName":"Sample",
				"definitiveOid":[{"name":"iso","number":"1"}],
				"iri":"\"/ISO\"","encodingReference":"XER",
				"tagDefault":"AUTOMATIC","extensibility":true}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _Parse(t, test.source), test.want)
		})
	}
}

// TestParseModulesValid checks ParseModulesValid.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestParseModulesValid(t *testing.T) {
	modules, err := ParseModules([]byte("Sample DEFINITIONS ::= BEGIN END"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(modules))
	}

	if modules[0].GetModuleName() != "Sample" {
		t.Errorf("got module name %q, want %q", modules[0].GetModuleName(), "Sample")
	}
}

// TestParseModulesMultiple checks ParseModulesMultiple.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestParseModulesMultiple(t *testing.T) {
	source := []byte("First DEFINITIONS ::= BEGIN END Second DEFINITIONS ::= BEGIN END")

	modules, err := ParseModules(source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(modules) != 2 {
		t.Fatalf("got %d modules, want 2", len(modules))
	}

	if modules[0].GetModuleName() != "First" {
		t.Errorf("got module name %q, want %q", modules[0].GetModuleName(), "First")
	}

	if modules[1].GetModuleName() != "Second" {
		t.Errorf("got module name %q, want %q", modules[1].GetModuleName(), "Second")
	}
}

// TestParseModuleBody checks the X.680 ModuleBody frame - the exports and
// imports clauses - including the three states each clause can be in:
// absent, present but naming nothing, and present with symbols. X.680
// 13.16 d) and 13.17 give "IMPORTS;" and an absent IMPORTS different
// meanings, so the AST has to keep them apart and so do these cases.
//
// Revisions:
//   - 2026-09-24 10:02: initial creation
func TestParseModuleBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "exports all",
			body: "EXPORTS ALL;",
			want: `{"exports":{"all":true}}`,
		},
		{
			name: "exports nothing",
			body: "EXPORTS;",
			want: `{"exports":{}}`,
		},
		{
			name: "exports symbols",
			body: "EXPORTS Foo, bar, Baz{};",
			want: `{"exports":{"symbols":[
				{"name":"Foo"},{"name":"bar"},
				{"name":"Baz","parameterized":true}]}}`,
		},
		{
			name: "imports nothing",
			body: "IMPORTS;",
			want: `{"imports":{}}`,
		},
		{
			name: "imports from one module",
			body: "IMPORTS Person, Colour FROM Other;",
			want: `{"imports":{"modules":[
				{"symbols":[{"name":"Person"},{"name":"Colour"}],
				 "moduleName":"Other"}]}}`,
		},
		{
			name: "imports from two modules",
			body: "IMPORTS Person FROM One Colour, size FROM Two;",
			want: `{"imports":{"modules":[
				{"symbols":[{"name":"Person"}],"moduleName":"One"},
				{"symbols":[{"name":"Colour"},{"name":"size"}],
				 "moduleName":"Two"}]}}`,
		},
		{
			name: "imports with assigned oid and selection option",
			body: "IMPORTS Person FROM Other { iso(1) three(3) } " +
				"WITH SUCCESSORS;",
			want: `{"imports":{"modules":[
				{"symbols":[{"name":"Person"}],"moduleName":"Other",
				 "oid":{"arcs":[{"name":"iso","number":"1"},
				                {"name":"three","number":"3"}]},
				 "selectionOption":"SUCCESSORS"}]}}`,
		},
		{
			name: "exports and imports together",
			body: "EXPORTS ALL; IMPORTS Person FROM Other;",
			want: `{"exports":{"all":true},"imports":{"modules":[
				{"symbols":[{"name":"Person"}],"moduleName":"Other"}]}}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			module := _Parse(
				t, "Sample DEFINITIONS ::= BEGIN "+test.body+" END",
			)

			// Every case names the same module, so the expectation says
			// only what the clause under test put there.
			module.ModuleName = ""
			_Want(t, module, test.want)
		})
	}
}

// TestParseAssignments checks the X.680 AssignmentList, so far only its
// TypeAssignment alternative and only the built-in types that have no
// inner type of their own. The two that carry a list of names - INTEGER
// and BIT STRING - are here because that list is where an identifier and
// a number meet a type, which is the first place a reader of the grammar
// has to ask which of the two a token belongs to.
//
// Revisions:
//   - 2026-09-24 10:52: initial creation
func TestParseAssignments(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "boolean",
			body: "Flag ::= BOOLEAN",
			want: `[{"name":"Flag","type":{"builtin":{"name":"BOOLEAN"}}}]`,
		},
		{
			name: "octet string",
			body: "Data ::= OCTET STRING",
			want: `[{"name":"Data",
				"type":{"builtin":{"name":"OCTET STRING"}}}]`,
		},
		{
			name: "object identifier",
			body: "Oid ::= OBJECT IDENTIFIER",
			want: `[{"name":"Oid",
				"type":{"builtin":{"name":"OBJECT IDENTIFIER"}}}]`,
		},
		{
			name: "character string",
			body: "Text ::= UTF8String",
			want: `[{"name":"Text","type":{"builtin":{"name":"UTF8String"}}}]`,
		},
		{
			name: "useful type",
			body: "Stamp ::= GeneralizedTime",
			want: `[{"name":"Stamp",
				"type":{"builtin":{"name":"GeneralizedTime"}}}]`,
		},
		{
			name: "integer with named numbers",
			body: "Level ::= INTEGER { low(1), high(10) }",
			want: `[{"name":"Level","type":{"builtin":{"name":"INTEGER",
				"named":[{"name":"low","number":"1"},
				         {"name":"high","number":"10"}]}}}]`,
		},
		{
			name: "named number that is negative",
			body: "Temp ::= INTEGER { freezing(-5) }",
			want: `[{"name":"Temp","type":{"builtin":{"name":"INTEGER",
				"named":[{"name":"freezing","number":"-5"}]}}}]`,
		},
		{
			name: "named number that names a value",
			body: "Level ::= INTEGER { lowest(minimum) }",
			want: `[{"name":"Level","type":{"builtin":{"name":"INTEGER",
				"named":[{"name":"lowest","reference":"minimum"}]}}}]`,
		},
		{
			name: "bit string with named bits",
			body: "Flags ::= BIT STRING { unread(0), urgent(1) }",
			want: `[{"name":"Flags","type":{"builtin":{"name":"BIT STRING",
				"named":[{"name":"unread","number":"0"},
				         {"name":"urgent","number":"1"}]}}}]`,
		},
		{
			name: "referenced type",
			body: "Alias ::= Level",
			want: `[{"name":"Alias","type":{"reference":{"name":"Level"}}}]`,
		},
		{
			name: "external type reference",
			body: "Remote ::= Other.Thing",
			want: `[{"name":"Remote",
				"type":{"reference":{"module":"Other","name":"Thing"}}}]`,
		},
		{
			name: "several assignments",
			body: "Flag ::= BOOLEAN Count ::= INTEGER",
			want: `[{"name":"Flag","type":{"builtin":{"name":"BOOLEAN"}}},
			        {"name":"Count","type":{"builtin":{"name":"INTEGER"}}}]`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			module := _Parse(
				t, "Sample DEFINITIONS ::= BEGIN "+test.body+" END",
			)

			module.ModuleName = ""
			_Want(t, module, `{"assignments":`+test.want+`}`)
		})
	}
}

// TestParseValueAssignments checks X.680's ValueAssignment. Value notation
// is read against the type a value was written for, which a context-free
// grammar cannot do, so most of what is checked here is that a value keeps
// the shape and the text it was written in: "42" and "myValue" are told
// apart because their tokens differ, while an INTEGER's "myValue" and an
// ENUMERATED's are the same to this grammar and stay that way.
//
// Revisions:
//   - 2026-09-24 11:18: initial creation
func TestParseValueAssignments(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "boolean",
			body: "flag BOOLEAN ::= TRUE",
			want: `{"name":"flag","value":{"type":{"builtin":{"name":"BOOLEAN"}},
				"value":{"boolean":true}}}`,
		},
		{
			name: "integer",
			body: "count INTEGER ::= 42",
			want: `{"name":"count","value":{"type":{"builtin":{"name":"INTEGER"}},
				"value":{"number":"42"}}}`,
		},
		{
			name: "negative integer",
			body: "temp INTEGER ::= -5",
			want: `{"name":"temp","value":{"type":{"builtin":{"name":"INTEGER"}},
				"value":{"number":"-5"}}}`,
		},
		{
			// An ASN.1 INTEGER has no bound, so the digits a module wrote
			// are kept rather than a number parsed out of them.
			name: "integer too large for a float",
			body: "big INTEGER ::= 123456789012345678901234567890",
			want: `{"name":"big","value":{"type":{"builtin":{"name":"INTEGER"}},
				"value":{"number":"123456789012345678901234567890"}}}`,
		},
		{
			name: "real",
			body: "pi REAL ::= 3.14159",
			want: `{"name":"pi","value":{"type":{"builtin":{"name":"REAL"}},
				"value":{"real":"3.14159"}}}`,
		},
		{
			name: "special real",
			body: "unbounded REAL ::= PLUS-INFINITY",
			want: `{"name":"unbounded","value":{"type":{"builtin":{"name":"REAL"}},
				"value":{"special":"PLUS-INFINITY"}}}`,
		},
		{
			name: "null",
			body: "nothing NULL ::= NULL",
			want: `{"name":"nothing","value":{"type":{"builtin":{"name":"NULL"}},
				"value":{"special":"NULL"}}}`,
		},
		{
			name: "binary string",
			body: "bits BIT STRING ::= '1010'B",
			want: `{"name":"bits",
				"value":{"type":{"builtin":{"name":"BIT STRING"}},
				"value":{"text":"'1010'B"}}}`,
		},
		{
			name: "hexadecimal string",
			body: "data OCTET STRING ::= '1A2B'H",
			want: `{"name":"data",
				"value":{"type":{"builtin":{"name":"OCTET STRING"}},
				"value":{"text":"'1A2B'H"}}}`,
		},
		{
			name: "character string",
			body: `greeting UTF8String ::= "hello"`,
			want: `{"name":"greeting",
				"value":{"type":{"builtin":{"name":"UTF8String"}},
				"value":{"text":"\"hello\""}}}`,
		},
		{
			name: "a name, which the type decides the meaning of",
			body: "alias INTEGER ::= count",
			want: `{"name":"alias","value":{"type":{"builtin":{"name":"INTEGER"}},
				"value":{"named":"count"}}}`,
		},
		{
			name: "a name qualified by its module",
			body: "alias INTEGER ::= Other.count",
			want: `{"name":"alias","value":{"type":{"builtin":{"name":"INTEGER"}},
				"value":{"named":"Other.count"}}}`,
		},
		{
			name: "value of a referenced type",
			body: "level Severity ::= high",
			want: `{"name":"level",
				"value":{"type":{"reference":{"name":"Severity"}},
				"value":{"named":"high"}}}`,
		},
		{
			name: "choice",
			body: "shape Shape ::= circle : 5",
			want: `{"name":"shape","value":{"type":{"reference":{"name":"Shape"}},
				"value":{"choice":{"name":"circle",
					"value":{"number":"5"}}}}}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseAssignment(t, test.body), test.want)
		})
	}
}

// TestParseConstructedTypes checks the types that hold other types -
// SEQUENCE, SET, CHOICE, the two OF forms - and ENUMERATED, which shares
// their braced list. What each case is really checking is where the
// extension markers end up: the list is parsed flat, with "..." and the
// "[[ ]]" groups as entries of their own, so a case that puts a marker in
// the middle has to come back with it in the middle.
//
// Revisions:
//   - 2026-09-24 11:46: initial creation
func TestParseConstructedTypes(t *testing.T) {
	// The component every nested case repeats, named so the cases below
	// stay inside the column limit.
	const INNER = `{"builtin":{"name":"SEQUENCE","components":[
		{"named":{"name":"a","type":{"builtin":{"name":"INTEGER"}}}}]}}`

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty sequence",
			body: "Empty ::= SEQUENCE { }",
			want: `{"builtin":{"name":"SEQUENCE"}}`,
		},
		{
			name: "sequence with components",
			body: "Person ::= SEQUENCE { name IA5String, age INTEGER }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"named":{"name":"name","type":{"builtin":{"name":"IA5String"}}}},
				{"named":{"name":"age","type":{"builtin":{"name":"INTEGER"}}}}]}}`,
		},
		{
			name: "optional and default",
			body: "Person ::= SEQUENCE { age INTEGER OPTIONAL, " +
				"male BOOLEAN DEFAULT TRUE }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"named":{"name":"age","type":{"builtin":{"name":"INTEGER"}},
					"optional":true}},
				{"named":{"name":"male","type":{"builtin":{"name":"BOOLEAN"}},
					"default":{"boolean":true}}}]}}`,
		},
		{
			name: "extension marker in the middle",
			body: "Open ::= SEQUENCE { a INTEGER, ..., b BOOLEAN }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"named":{"name":"a","type":{"builtin":{"name":"INTEGER"}}}},
				{"marker":{}},
				{"named":{"name":"b","type":{"builtin":{"name":"BOOLEAN"}}}}]}}`,
		},
		{
			name: "extension addition group",
			body: "Open ::= SEQUENCE { a INTEGER, ..., [[ 2: b BOOLEAN ]] }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"named":{"name":"a","type":{"builtin":{"name":"INTEGER"}}}},
				{"marker":{}},
				{"group":{"version":2,"components":[
					{"named":{"name":"b",
						"type":{"builtin":{"name":"BOOLEAN"}}}}]}}]}}`,
		},
		{
			name: "components of",
			body: "Sub ::= SEQUENCE { COMPONENTS OF Person }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"of":{"type":{"reference":{"name":"Person"}}}}]}}`,
		},
		{
			name: "set",
			body: "Bag ::= SET { a INTEGER }",
			want: `{"builtin":{"name":"SET","components":[
				{"named":{"name":"a","type":{"builtin":{"name":"INTEGER"}}}}]}}`,
		},
		{
			name: "sequence of",
			body: "List ::= SEQUENCE OF INTEGER",
			want: `{"builtin":{"name":"SEQUENCE OF",
				"element":{"builtin":{"name":"INTEGER"}}}}`,
		},
		{
			name: "sequence of a named element",
			body: "List ::= SEQUENCE OF item INTEGER",
			want: `{"builtin":{"name":"SEQUENCE OF",
				"element":{"builtin":{"name":"INTEGER"}},"elementName":"item"}}`,
		},
		{
			name: "set of a referenced type",
			body: "Bag ::= SET OF Person",
			want: `{"builtin":{"name":"SET OF",
				"element":{"reference":{"name":"Person"}}}}`,
		},
		{
			name: "choice",
			body: "Shape ::= CHOICE { circle INTEGER, ..., square BOOLEAN }",
			want: `{"builtin":{"name":"CHOICE","components":[
				{"named":{"name":"circle","type":{"builtin":{"name":"INTEGER"}}}},
				{"marker":{}},
				{"named":{"name":"square",
					"type":{"builtin":{"name":"BOOLEAN"}}}}]}}`,
		},
		{
			name: "enumerated",
			body: "Colour ::= ENUMERATED { red, green, ... }",
			want: `{"builtin":{"name":"ENUMERATED","components":[
				{"named":{"name":"red"}},{"named":{"name":"green"}},
				{"marker":{}}]}}`,
		},
		{
			name: "enumerated with numbers",
			body: "Colour ::= ENUMERATED { red(1), green(2) }",
			want: `{"builtin":{"name":"ENUMERATED","components":[
				{"named":{"name":"red","number":{"number":"1"}}},
				{"named":{"name":"green","number":{"number":"2"}}}]}}`,
		},
		{
			name: "nested sequence",
			body: "Outer ::= SEQUENCE { inner SEQUENCE { a INTEGER } }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"named":{"name":"inner","type":` + INNER + `}}]}}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseType(t, test.body), test.want)
		})
	}
}

// TestParseConstraints checks X.680's constraint notation, clauses 49 to
// 51. The cases are the forms the specifications under specs/ and the
// files under samples/ actually write, plus the two that decide whether
// the set expression was built right: a chain of "|", which must nest to
// the left, and an EXCEPT, which binds tighter than either mark.
//
// Revisions:
//   - 2026-09-24 12:14: initial creation
func TestParseConstraints(t *testing.T) {
	// The constraint inside the partial WITH COMPONENTS case, named here
	// rather than written into the table, which would indent it past the
	// line limit.
	const ADULT = `{"root":{"range":{"lower":{"number":"18"},
		"upper":{"special":"MAX"}}}}`

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "value range",
			body: "Small ::= INTEGER (1..10)",
			want: `[{"root":{"range":{"lower":{"number":"1"},
				"upper":{"number":"10"}}}}]`,
		},
		{
			name: "range open at the top",
			body: "Semi ::= INTEGER (-1..MAX)",
			want: `[{"root":{"range":{"lower":{"number":"-1"},
				"upper":{"special":"MAX"}}}}]`,
		},
		{
			name: "endpoints excluded",
			body: "Between ::= INTEGER (1<..<10)",
			want: `[{"root":{"range":{"lower":{"number":"1"},
				"upper":{"number":"10"},"lowerOpen":true,
				"upperOpen":true}}}]`,
		},
		{
			name: "extensible",
			body: "Open ::= INTEGER (0..MAX, ...)",
			want: `[{"root":{"range":{"lower":{"number":"0"},
				"upper":{"special":"MAX"}}},"extensible":true}]`,
		},
		{
			name: "extensible with additions",
			body: "Open ::= INTEGER (1..10, ..., 20..30)",
			want: `[{"root":{"range":{"lower":{"number":"1"},
				"upper":{"number":"10"}}},"extensible":true,
				"additional":{"range":{"lower":{"number":"20"},
				"upper":{"number":"30"}}}}]`,
		},
		{
			name: "union of single values",
			body: "Pick ::= INTEGER (2 | 10)",
			want: `[{"root":{"union":{"operands":[
				{"value":{"number":"2"}},{"value":{"number":"10"}}]}}}]`,
		},
		{
			name: "size",
			body: "Bits ::= BIT STRING (SIZE (1..MAX))",
			want: `[{"root":{"size":{"root":{"range":{"lower":{"number":"1"},
				"upper":{"special":"MAX"}}}}}}]`,
		},
		{
			name: "size of one value",
			body: "Fixed ::= BIT STRING (SIZE (8))",
			want: `[{"root":{"size":{"root":{"value":{"number":"8"}}}}}]`,
		},
		{
			name: "permitted alphabet",
			body: `Text ::= IA5String (FROM ("abc"))`,
			want: `[{"root":{"alphabet":{"root":{"value":
				{"text":"\"abc\""}}}}}]`,
		},
		{
			name: "except binds tighter than a union",
			body: "Exc ::= INTEGER (1..10 EXCEPT 5)",
			want: `[{"root":{"except":{"operands":[
				{"range":{"lower":{"number":"1"},"upper":{"number":"10"}}},
				{"value":{"number":"5"}}]}}}]`,
		},
		{
			name: "all except",
			body: "Rest ::= INTEGER (ALL EXCEPT 5)",
			want: `[{"root":{"all":{"value":{"number":"5"}}}}]`,
		},
		{
			name: "contained subtype",
			body: "Sub ::= INTEGER (INCLUDES Other)",
			want: `[{"root":{"type":{"reference":{"name":"Other"}}}}]`,
		},
		{
			name: "contained subtype without the keyword",
			body: "Sub ::= INTEGER (Other)",
			want: `[{"root":{"type":{"reference":{"name":"Other"}}}}]`,
		},
		{
			name: "with component",
			body: "Few ::= Bag (WITH COMPONENT (1..5))",
			want: `[{"root":{"component":{"root":{"range":
				{"lower":{"number":"1"},"upper":{"number":"5"}}}}}}]`,
		},
		{
			name: "with components",
			body: "Adult ::= Person (WITH COMPONENTS { age PRESENT })",
			want: `[{"root":{"components":{"named":[
				{"name":"age","presence":"PRESENT"}]}}}]`,
		},
		{
			name: "with components, partial and constrained",
			body: "Adult ::= Person (WITH COMPONENTS { ..., " +
				"age (18..MAX) PRESENT, name ABSENT })",
			want: `[{"root":{"components":{"partial":true,"named":[
				{"name":"age","constraint":` + ADULT + `,
				 "presence":"PRESENT"},
				{"name":"name","presence":"ABSENT"}]}}}]`,
		},
		{
			name: "user defined, with no parameters",
			body: "Odd ::= INTEGER (CONSTRAINED BY { })",
			want: `[{"root":{"user":{}}}]`,
		},
		{
			name: "user defined, with a governed parameter",
			body: "Odd ::= INTEGER (CONSTRAINED BY { INTEGER : 3, Rule })",
			want: `[{"root":{"user":{"settings":[
				{"value":{"open":{"type":{"builtin":{"name":"INTEGER"}},
					"value":{"number":"3"}}}},
				{"type":{"reference":{"name":"Rule"}}}]}}}]`,
		},
		{
			name: "two constraints in a row",
			body: `Text ::= IA5String (SIZE (1..4))(FROM ("ab"))`,
			want: `[{"root":{"size":{"root":{"range":{"lower":{"number":"1"},
				"upper":{"number":"4"}}}}}},
			        {"root":{"alphabet":{"root":{"value":
				{"text":"\"ab\""}}}}}]`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			node := _ParseType(t, test.body)

			// The constraints are what is under test, so they are lifted
			// out of the type that carries them.
			_Want(t, &ast.Type{Constraints: node.GetConstraints()},
				`{"constraints":`+test.want+`}`)
		})
	}
}

// TestParseSizedCollections checks the X.680 TypeWithConstraint forms,
// where a SEQUENCE OF or SET OF carries its size between the keyword and
// the OF rather than after the whole type. Both spellings X.680 allows
// are here, with and without the parentheses around SIZE.
//
// Revisions:
//   - 2026-09-24 12:14: initial creation
func TestParseSizedCollections(t *testing.T) {
	const WANT = `{"builtin":{"name":"SEQUENCE OF",
		"element":{"builtin":{"name":"INTEGER"}}},
		"constraints":[{"root":{"size":{"root":{"range":
			{"lower":{"number":"1"},"upper":{"number":"4"}}}}}}]}`

	cases := []struct {
		name string
		body string
	}{
		{
			name: "size in parentheses",
			body: "List ::= SEQUENCE (SIZE (1..4)) OF INTEGER",
		},
		{
			name: "size without parentheses",
			body: "List ::= SEQUENCE SIZE (1..4) OF INTEGER",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseType(t, test.body), WANT)
		})
	}
}

// TestParseBracedValues checks the values X.680 writes between braces.
// They are all one rule, because the same tokens mean different things
// depending on the type the value was written for and this grammar has no
// type to read them against: "{ a, b }" is a BIT STRING's identifier list
// and a SEQUENCE OF's value list alike, and "{ iso 42 }" is an object
// identifier's two arcs and a SEQUENCE's one named component alike.
//
// What the grammar does record is the shape: where the commas were, and
// how many values a module wrote between each pair of them. Every case
// below is really a check on that - the entry counts and the run lengths
// are what a later pass reads the value from.
//
// Revisions:
//   - 2026-09-24 12:42: initial creation
func TestParseBracedValues(t *testing.T) {
	// The two inner values of the nesting case, named here rather than
	// written into the table, which would indent them past the limit.
	const FIRST = `{"braced":{"elements":[
		{"values":{"values":[{"number":"1"}]}},
		{"values":{"values":[{"number":"2"}]}}]}}`

	const SECOND = `{"braced":{"elements":[
		{"values":{"values":[{"number":"3"}]}}]}}`

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty",
			body: "v Foo ::= { }",
			want: `{"braced":{}}`,
		},
		{
			name: "a list of names, one to an entry",
			body: "v BIT STRING ::= { unread, urgent }",
			want: `{"braced":{"elements":[
				{"values":{"values":[{"named":"unread"}]}},
				{"values":{"values":[{"named":"urgent"}]}}]}}`,
		},
		{
			name: "a list of values, one to an entry",
			body: "v Foo ::= { 1, 2, 3 }",
			want: `{"braced":{"elements":[
				{"values":{"values":[{"number":"1"}]}},
				{"values":{"values":[{"number":"2"}]}},
				{"values":{"values":[{"number":"3"}]}}]}}`,
		},
		{
			name: "named components, two values to an entry",
			body: `v Person ::= { name "John Doe", age 42 }`,
			want: `{"braced":{"elements":[
				{"values":{"values":[{"named":"name"},
					{"text":"\"John Doe\""}]}},
				{"values":{"values":[{"named":"age"},
					{"number":"42"}]}}]}}`,
		},
		{
			name: "object identifier arcs, one entry of three",
			body: "v OBJECT IDENTIFIER ::= { iso member-body 42 }",
			want: `{"braced":{"elements":[
				{"values":{"values":[{"named":"iso"},
					{"named":"member-body"},{"number":"42"}]}}]}}`,
		},
		{
			name: "arcs that name their number",
			body: "v OBJECT IDENTIFIER ::= { iso(1) member-body(2) }",
			want: `{"braced":{"elements":[{"values":{"values":[
				{"namedNumber":{"name":"iso","number":{"number":"1"}}},
				{"namedNumber":{"name":"member-body",
					"number":{"number":"2"}}}]}}]}}`,
		},
		{
			name: "braced values inside a braced value",
			body: "v Foo ::= { { 1, 2 }, { 3 } }",
			want: `{"braced":{"elements":[
				{"values":{"values":[` + FIRST + `]}},
				{"values":{"values":[` + SECOND + `]}}]}}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			node := _ParseAssignment(t, test.body)
			_Want(t, node.GetValue().GetValue(), test.want)
		})
	}
}

// TestParseTaggedTypes checks X.680 clause 31. A tag is recorded on the
// type it tags rather than wrapping it in a level of its own, which is
// why the last case matters: a constraint written after a tagged type
// binds to the type, and both end up on the same node.
//
// Revisions:
//   - 2026-09-24 13:08: initial creation
func TestParseTaggedTypes(t *testing.T) {
	const INTEGER_TYPE = `"builtin":{"name":"INTEGER"}`

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "context specific",
			body: "A ::= [0] INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"number":{"number":"0"}}]}`,
		},
		{
			name: "implicit",
			body: "A ::= [0] IMPLICIT INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"number":{"number":"0"},"mode":"IMPLICIT"}]}`,
		},
		{
			name: "explicit",
			body: "A ::= [0] EXPLICIT INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"number":{"number":"0"},"mode":"EXPLICIT"}]}`,
		},
		{
			name: "universal class",
			body: "A ::= [UNIVERSAL 31] IMPLICIT TIME",
			want: `{"builtin":{"name":"TIME"},
				"tags":[{"class":"UNIVERSAL","number":{"number":"31"},
					"mode":"IMPLICIT"}]}`,
		},
		{
			name: "application class",
			body: "A ::= [APPLICATION 1] INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"class":"APPLICATION","number":{"number":"1"}}]}`,
		},
		{
			name: "private class",
			body: "A ::= [PRIVATE 2] INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"class":"PRIVATE","number":{"number":"2"}}]}`,
		},
		{
			name: "number named elsewhere",
			body: "A ::= [myTag] INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"number":{"named":"myTag"}}]}`,
		},
		{
			name: "qualified by an encoding reference",
			body: "A ::= [XER: 0] INTEGER",
			want: `{` + INTEGER_TYPE + `,
				"tags":[{"number":{"number":"0"},
					"encodingReference":"XER"}]}`,
		},
		{
			name: "a tag on a tagged type, outermost first",
			body: "A ::= [0] [1] IMPLICIT INTEGER",
			want: `{` + INTEGER_TYPE + `,"tags":[
				{"number":{"number":"0"}},
				{"number":{"number":"1"},"mode":"IMPLICIT"}]}`,
		},
		{
			name: "a constraint after a tagged type binds to the type",
			body: `A ::= [UNIVERSAL 31] IMPLICIT TIME (SETTINGS "Basic=Date")`,
			want: `{"builtin":{"name":"TIME"},
				"tags":[{"class":"UNIVERSAL","number":{"number":"31"},
					"mode":"IMPLICIT"}],
				"constraints":[{"root":{"settings":
					"\"Basic=Date\""}}]}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseType(t, test.body), test.want)
		})
	}
}

// TestParseRemainingX680 checks the pieces of X.680 that were left for
// last because nothing under samples/ uses them: the exception marker,
// selection types, value set type assignments and the contents
// constraint. Each is small, and each is here because a grammar that
// covers X.680 and not these covers X.680 almost.
//
// Revisions:
//   - 2026-09-24 13:34: initial creation
func TestParseRemainingX680(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "exception on an extension marker",
			body: "A ::= SEQUENCE { a INTEGER, ...!5 }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"named":{"name":"a","type":{"builtin":{"name":"INTEGER"}}}},
				{"marker":{"exception":{"value":{"number":"5"}}}}]}}`,
		},
		{
			name: "exception naming the type of its value",
			body: "A ::= SEQUENCE { ...!Fault : 3 }",
			want: `{"builtin":{"name":"SEQUENCE","components":[
				{"marker":{"exception":{
					"type":{"reference":{"name":"Fault"}},
					"value":{"number":"3"}}}}]}}`,
		},
		{
			name: "exception on a constraint",
			body: "A ::= INTEGER (1..10 ! myFault)",
			want: `{"builtin":{"name":"INTEGER"},"constraints":[
				{"root":{"range":{"lower":{"number":"1"},
					"upper":{"number":"10"}}},
				 "exception":{"value":{"named":"myFault"}}}]}`,
		},
		{
			name: "selection type",
			body: "A ::= circle < Shape",
			want: `{"selection":{"name":"circle",
				"from":{"reference":{"name":"Shape"}}}}`,
		},
		{
			name: "contents constraint",
			body: "A ::= OCTET STRING (CONTAINING Inner)",
			want: `{"builtin":{"name":"OCTET STRING"},"constraints":[
				{"root":{"contents":{
					"type":{"reference":{"name":"Inner"}}}}}]}`,
		},
		{
			name: "contents constraint with an encoding",
			body: "A ::= OCTET STRING (CONTAINING I ENCODED BY ber)",
			want: `{"builtin":{"name":"OCTET STRING"},"constraints":[
				{"root":{"contents":{"type":{"reference":{"name":"I"}},
					"value":{"named":"ber"}}}}]}`,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseType(t, test.body), test.want)
		})
	}

	t.Run("value set type assignment", func(t *testing.T) {
		got := _ParseAssignment(t, "Small INTEGER ::= { 1 | 2 }")

		_Want(t, got, `{"name":"Small","valueSet":{
			"type":{"builtin":{"name":"INTEGER"}},
			"set":{"root":{"union":{"operands":[
				{"value":{"number":"1"}},
				{"value":{"number":"2"}}]}}}}}`)
	})
}

// TestParseParameterization checks X.683. A parameterized definition is
// told from an ordinary one by the brace after its name, which nothing
// else can be: no Type begins with one. What an actual parameter means -
// a type, a value, a value set or an object - is the formal parameter's
// governor's business, so the cases below check only which shape was
// written.
//
// Revisions:
//   - 2026-09-24 14:06: initial creation
func TestParseParameterization(t *testing.T) {
	assignments := []struct {
		name string
		body string
		want string
	}{
		{
			name: "parameterized type assignment",
			body: "Pair { Item } ::= SEQUENCE OF Item",
			want: `{"name":"Pair","parameters":[{"name":"Item"}],
				"type":{"builtin":{"name":"SEQUENCE OF",
					"element":{"reference":{"name":"Item"}}}}}`,
		},
		{
			name: "governed parameter",
			body: "Small { INTEGER : top } ::= INTEGER",
			want: `{"name":"Small","parameters":[
				{"governor":{"builtin":{"name":"INTEGER"}},"name":"top"}],
				"type":{"builtin":{"name":"INTEGER"}}}`,
		},
		{
			name: "several parameters",
			body: "P { Key, Value } ::= SEQUENCE OF Key",
			want: `{"name":"P",
				"parameters":[{"name":"Key"},{"name":"Value"}],
				"type":{"builtin":{"name":"SEQUENCE OF",
					"element":{"reference":{"name":"Key"}}}}}`,
		},
		{
			name: "parameterized value assignment",
			body: "top { Bound } Bound ::= 5",
			want: `{"name":"top","parameters":[{"name":"Bound"}],
				"value":{"type":{"reference":{"name":"Bound"}},
					"value":{"number":"5"}}}`,
		},
		{
			name: "parameterized value set type assignment",
			body: "Few { Item } Item ::= { 1 | 2 }",
			want: `{"name":"Few","parameters":[{"name":"Item"}],
				"valueSet":{"type":{"reference":{"name":"Item"}},
					"set":{"root":{"union":{"operands":[
						{"value":{"number":"1"}},
						{"value":{"number":"2"}}]}}}}}`,
		},
	}

	for _, test := range assignments {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseAssignment(t, test.body), test.want)
		})
	}

	types := []struct {
		name string
		body string
		want string
	}{
		{
			name: "used with a type argument",
			body: "Names ::= Pair { IA5String }",
			want: `{"reference":{"name":"Pair","arguments":[
				{"type":{"builtin":{"name":"IA5String"}}}]}}`,
		},
		{
			name: "used with a value argument",
			body: "Ten ::= Small { 10 }",
			want: `{"reference":{"name":"Small","arguments":[
				{"value":{"number":"10"}}]}}`,
		},
	}

	for _, test := range types {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseType(t, test.body), test.want)
		})
	}
}

// TestParseObjectClasses checks the class definitions of X.681 clause 9,
// and the two places a class reaches a type: an object class field type
// and INSTANCE OF. The field specs are what the cases mostly check,
// because X.681's seven kinds of field are two rules here - the lexer
// has "&Upper" and "&lower" and nothing finer - so each case is really
// asking that a field's governor survives whichever kind it was.
//
// Revisions:
//   - 2026-09-24 14:41: initial creation
func TestParseObjectClasses(t *testing.T) {
	assignments := []struct {
		name string
		body string
		want string
	}{
		{
			name: "class with a fixed type value field",
			body: "FOO ::= CLASS { &id INTEGER UNIQUE }",
			want: `{"name":"FOO","class":{"fields":[
				{"name":"&id","governor":{"builtin":{"name":"INTEGER"}},
				 "unique":true}]}}`,
		},
		{
			name: "open type field",
			body: "FOO ::= CLASS { &Type OPTIONAL }",
			want: `{"name":"FOO","class":{"fields":[
				{"name":"&Type","optional":true}]}}`,
		},
		{
			name: "field with a default type",
			body: "FOO ::= CLASS { &Type DEFAULT BOOLEAN }",
			want: `{"name":"FOO","class":{"fields":[
				{"name":"&Type","default":
					{"type":{"builtin":{"name":"BOOLEAN"}}}}]}}`,
		},
		{
			name: "field governed by another field",
			body: "FOO ::= CLASS { &Type, &value &Type }",
			want: `{"name":"FOO","class":{"fields":[
				{"name":"&Type"},
				{"name":"&value","path":["&Type"]}]}}`,
		},
		{
			name: "object field governed by a class",
			body: "FOO ::= CLASS { &obj OTHER-CLASS }",
			want: `{"name":"FOO","class":{"fields":[
				{"name":"&obj",
				 "governor":{"reference":{"name":"OTHER-CLASS"}}}]}}`,
		},
		{
			name: "a class named rather than defined",
			body: "FOO ::= TYPE-IDENTIFIER",
			want: `{"name":"FOO","class":{"reference":"TYPE-IDENTIFIER"}}`,
		},
		{
			name: "with syntax",
			body: "FOO ::= CLASS { &id INTEGER, &Type } " +
				"WITH SYNTAX { ID &id TYPE &Type }",
			want: `{"name":"FOO","class":{
				"fields":[
					{"name":"&id","governor":{"builtin":{"name":"INTEGER"}}},
					{"name":"&Type"}],
				"syntax":[{"literal":"ID"},{"field":"&id"},
				          {"literal":"TYPE"},{"field":"&Type"}]}}`,
		},
		{
			name: "with syntax, optional group",
			body: "FOO ::= CLASS { &Type } " +
				"WITH SYNTAX { TYPE [ HAS &Type ] }",
			want: `{"name":"FOO","class":{
				"fields":[{"name":"&Type"}],
				"syntax":[{"literal":"TYPE"},
				          {"group":{"tokens":[{"literal":"HAS"},
				                              {"field":"&Type"}]}}]}}`,
		},
	}

	for _, test := range assignments {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseAssignment(t, test.body), test.want)
		})
	}

	types := []struct {
		name string
		body string
		want string
	}{
		{
			name: "object class field type",
			body: "A ::= FOO.&Type",
			want: `{"field":{"reference":"FOO","field":["&Type"]}}`,
		},
		{
			name: "field of a useful class",
			body: "A ::= TYPE-IDENTIFIER.&id",
			want: `{"field":{"reference":"TYPE-IDENTIFIER",
				"field":["&id"]}}`,
		},
		{
			name: "instance of",
			body: "A ::= INSTANCE OF FOO",
			want: `{"builtin":{"name":"INSTANCE OF",
				"element":{"reference":{"name":"FOO"}}}}`,
		},
	}

	for _, test := range types {
		t.Run(test.name, func(t *testing.T) {
			_Want(t, _ParseType(t, test.body), test.want)
		})
	}
}

// TestParseObjects checks that an information object reaches the AST as
// the text it was written with. Which of an object and a value a module
// meant is decided by the class, and no parser reads that, so the lexer
// keeps a braced group whole when what stands inside it cannot be a
// value - a field reference, or a typereference next to a name. The
// cases below are the two notations X.681 gives objects, an object set
// written with them, and the values that must keep parsing as values.
//
// Revisions:
//   - 2026-09-24 15:52: initial creation
func TestParseObjects(t *testing.T) {
	t.Run("object in the class's own syntax", func(t *testing.T) {
		got := _ParseAssignment(t, "obj FOO ::= { ID one TYPE Two }")

		_Want(t, got, `{"name":"obj","value":{
			"type":{"reference":{"name":"FOO"}},
			"value":{"opaque":"{ ID one TYPE Two }"}}}`)
	})

	// The default syntax is the one object notation a parser can read on
	// its own: its entries open with a field reference, which no value
	// has, and they are comma-separated rather than written side by side.
	// See the pattern section at the foot of grammar.y.
	t.Run("object in the default syntax", func(t *testing.T) {
		got := _ParseAssignment(t, "obj FOO ::= { &id 1, &Type INTEGER }")

		_Want(t, got.GetValue().GetValue(), `{"object":{"elements":[
			{"setting":{"field":"&id","value":{"value":{"number":"1"}}}},
			{"setting":{"field":"&Type",
				"value":{"type":{"builtin":{"name":"INTEGER"}}}}}]}}`)
	})

	// X.682's component relation constraint, which ties an open type to
	// the field that selects it. Also a pattern: the brace followed by an
	// at sign is what the lexer recognizes it by.
	relations := []struct {
		name string
		body string
		want string
	}{
		{
			name: "component relation constraint",
			body: "A ::= FOO.&Value ({Ies}{@id})",
			want: `[{"path":["id"]}]`,
		},
		{
			name: "component relation, outer level and a path",
			body: "A ::= FOO.&Value ({Ies}{@.hdr.id})",
			want: `[{"level":"1","path":["hdr","id"]}]`,
		},
	}

	for _, test := range relations {
		t.Run(test.name, func(t *testing.T) {
			node := _ParseType(t, test.body)

			constraints := node.GetConstraints()
			if len(constraints) != 1 {
				t.Fatalf("got %d constraints, want 1", len(constraints))
			}

			_Want(t,
				&ast.Constraint{Relation: constraints[0].GetRelation()},
				`{"relation":`+test.want+`}`)
		})
	}

	t.Run("object set", func(t *testing.T) {
		got := _ParseAssignment(t,
			"Ies FOO ::= { { ID a TYPE A } | { ID b TYPE B } }")

		set := got.GetValueSet().GetSet()
		if set.GetRoot().GetUnion() == nil {
			t.Fatalf("got no union at the root: %s", _JSON(got))
		}

		for index, operand := range set.GetRoot().GetUnion().GetOperands() {
			if operand.GetValue().GetOpaque() == "" {
				t.Errorf("operand %d is not an object: %s",
					index, _JSON(operand))
			}
		}
	})

	t.Run("a group that nests an object stays whole", func(t *testing.T) {
		got := _ParseAssignment(t, "obj FOO ::= { ARG Arg ERRORS {e1 | e2} }")
		want := "{ ARG Arg ERRORS {e1 | e2} }"

		if opaque := got.GetValue().GetValue().GetOpaque(); opaque != want {
			t.Errorf("got %q, want %q", opaque, want)
		}
	})

	// The lexer's test has to leave every one of these alone, or the
	// value notation it took eleven changes to build stops working.
	t.Run("values are still values", func(t *testing.T) {
		cases := []string{
			"v Foo ::= { 1, 2, 3 }",
			"v OBJECT IDENTIFIER ::= { iso member-body 42 }",
			`v Person ::= { name "John Doe", age 42 }`,
			"v Foo ::= { { 1, 2 }, { 3 } }",
			"v Foo ::= { Other.thing, 1 }",
			"V Foo ::= { 1 | 2 }",
			"V Foo ::= { Other }",
			"F ::= CLASS { &id INTEGER, &Type }",
			"F ::= CLASS { &Type } WITH SYNTAX { ID &Type }",
			"S ::= SEQUENCE { a INTEGER, b Foo }",
			"E ::= ENUMERATED { red, green }",
			"I ::= INTEGER { low(1), high(2) }",
		}

		for _, body := range cases {
			source := "Sample DEFINITIONS ::= BEGIN " + body + " END"
			if _, err := ParseModules([]byte(source)); err != nil {
				t.Errorf("%s: %v", body, err)
			}
		}
	})
}

// TestParseInformationObjectModule parses a module in the shape the
// specifications this compiler is for actually write - a class, the
// syntax it declares, a type parameterized by it, a table constraint and
// an object set written in that syntax. Each piece has its own test
// above; this one is here because they were built separately and the
// shape only works if they fit together.
//
// Revisions:
//   - 2026-09-24 17:12: initial creation
func TestParseInformationObjectModule(t *testing.T) {
	source := `RANAP DEFINITIONS AUTOMATIC TAGS ::= BEGIN

RANAP-PROTOCOL-IES ::= CLASS {
    &id             ProtocolIE-ID   UNIQUE,
    &criticality    Criticality,
    &Value,
    &presence       Presence
} WITH SYNTAX {
    ID &id  CRITICALITY &criticality  TYPE &Value  PRESENCE &presence
}

ProtocolIE-Field {RANAP-PROTOCOL-IES : IEsSetParam} ::= SEQUENCE {
    id              RANAP-PROTOCOL-IES.&id          ({IEsSetParam}),
    criticality     RANAP-PROTOCOL-IES.&criticality,
    value           RANAP-PROTOCOL-IES.&Value
}

InitiatingMessageIEs RANAP-PROTOCOL-IES ::= {
    { ID id-Cause  CRITICALITY ignore  TYPE Cause  PRESENCE optional } |
    { ID id-RAB-ID CRITICALITY reject  TYPE RAB-ID PRESENCE mandatory }
}

END`

	modules, err := ParseModules([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assignments := modules[0].GetAssignments()
	if len(assignments) != 3 {
		t.Fatalf("got %d assignments, want 3", len(assignments))
	}

	class := assignments[0].GetClass()
	if len(class.GetFields()) != 4 {
		t.Errorf("got %d fields, want 4", len(class.GetFields()))
	}

	if len(class.GetSyntax()) != 8 {
		t.Errorf("got %d syntax tokens, want 8", len(class.GetSyntax()))
	}

	field := assignments[1]
	if len(field.GetParameters()) != 1 {
		t.Fatalf("got %d parameters, want 1", len(field.GetParameters()))
	}

	// The table constraint on the first component, which is what ties the
	// open type to the object set the parameter names.
	first := field.GetType().GetBuiltin().GetComponents()[0].GetNamed()
	if len(first.GetType().GetConstraints()) != 1 {
		t.Errorf("got %d constraints on %q",
			len(first.GetType().GetConstraints()), first.GetName())
	}

	set := assignments[2].GetValueSet().GetSet()
	if set.GetRoot().GetUnion() == nil {
		t.Fatalf("got no union of objects: %s", _JSON(assignments[2]))
	}

	for index, operand := range set.GetRoot().GetUnion().GetOperands() {
		if operand.GetValue().GetOpaque() == "" {
			t.Errorf("object %d did not survive whole: %s",
				index, _JSON(operand))
		}
	}
}

// TestParseEncodingControlSections checks X.680 clause 54. A section's
// body is kept as text because X.680 does not define it: the clause hands
// the contents to the encoding the section names, and X.693 and X.697
// define them for XER and JER. What is checked here is where a body
// begins and ends, which X.680 does say - it runs to the next section or
// to END.
//
// Revisions:
//   - 2026-09-24 17:55: initial creation
func TestParseEncodingControlSections(t *testing.T) {
	t.Run("one section", func(t *testing.T) {
		source := "Sample DEFINITIONS ::= BEGIN A ::= INTEGER " +
			"ENCODING-CONTROL XER GLOBAL-DEFAULTS MODIFIED-ENCODINGS END"

		modules, err := ParseModules([]byte(source))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_Want(t, &ast.Module{Sections: modules[0].GetSections()},
			`{"sections":[{"encodingReference":"XER",
				"text":"GLOBAL-DEFAULTS MODIFIED-ENCODINGS"}]}`)
	})

	t.Run("two sections", func(t *testing.T) {
		source := "Sample DEFINITIONS ::= BEGIN " +
			"ENCODING-CONTROL XER [NAME AS UNCAPITALIZED] " +
			"ENCODING-CONTROL PER a-b ALIGNED END"

		modules, err := ParseModules([]byte(source))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_Want(t, &ast.Module{Sections: modules[0].GetSections()},
			`{"sections":[
				{"encodingReference":"XER",
				 "text":"[NAME AS UNCAPITALIZED]"},
				{"encodingReference":"PER","text":"a-b ALIGNED"}]}`)
	})

	t.Run("a module with no sections has none", func(t *testing.T) {
		modules, err := ParseModules([]byte(
			"Sample DEFINITIONS ::= BEGIN A ::= INTEGER END",
		))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if modules[0].GetSections() != nil {
			t.Errorf("got %s, want none", _JSON(modules[0]))
		}
	})
}

// TestParseXMLValueAssignments checks X.680 16.2's XML value assignment.
// The element is kept as the text it was written as, because what an
// element holds is not ASN.1: X.680 gives XML content its own lexical
// items, and an ASN.1 lexer reading "<A>0101</A>" would find a number
// that is not one. What is checked here is where an element ends, which
// is the part that can be decided without knowing the type.
//
// Revisions:
//   - 2026-09-24 18:20: initial creation
func TestParseXMLValueAssignments(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "text content",
			body: "v ::= <Count>42</Count>",
			want: "<Count>42</Count>",
		},
		{
			name: "an empty element",
			body: "v ::= <Flag/>",
			want: "<Flag/>",
		},
		{
			name: "elements inside an element",
			body: "v ::= <Pair><a>1</a><b>2</b></Pair>",
			want: "<Pair><a>1</a><b>2</b></Pair>",
		},
		{
			name: "content an ASN.1 lexer would misread",
			body: "v ::= <Bits>0101</Bits>",
			want: "<Bits>0101</Bits>",
		},
		{
			name: "an empty element inside another",
			body: "v ::= <Pair><a/><b>2</b></Pair>",
			want: "<Pair><a/><b>2</b></Pair>",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := _ParseAssignment(t, test.body)

			_Want(t, got.GetValue().GetValue(),
				`{"xml":`+_Quoted(test.want)+`}`)
		})
	}

	// The type between the name and the "::=" is the whole of what
	// separates an ordinary value assignment from an XML one, so it is
	// worth checking that one still reaches the other rule.
	t.Run("an ordinary value assignment is untouched", func(t *testing.T) {
		got := _ParseAssignment(t, "v INTEGER ::= 5")

		_Want(t, got, `{"name":"v","value":{
			"type":{"builtin":{"name":"INTEGER"}},
			"value":{"number":"5"}}}`)
	})
}

// TestParseModulesInvalid checks ParseModulesInvalid.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-09-24 09:41: cases for the header's optional clauses
func TestParseModulesInvalid(t *testing.T) {
	cases := []string{
		"",
		"DEFINITIONS ::= BEGIN END",
		"Sample DEFINITIONS BEGIN END",
		"Sample DEFINITIONS ::= BEGIN",
		"sample DEFINITIONS ::= BEGIN END",
		"Sample { } DEFINITIONS ::= BEGIN END",
		`Sample "/ISO" DEFINITIONS ::= BEGIN END`,
		"Sample DEFINITIONS TAGS ::= BEGIN END",
		"Sample DEFINITIONS EXPLICIT ::= BEGIN END",
		"Sample DEFINITIONS EXTENSIBILITY ::= BEGIN END",
		"Sample DEFINITIONS AUTOMATIC TAGS EXPLICIT TAGS ::= BEGIN END",
		"Sample DEFINITIONS AUTOMATIC TAGS XER INSTRUCTIONS ::= BEGIN END",
		"Sample DEFINITIONS ::= BEGIN EXPORTS ALL END",
		"Sample DEFINITIONS ::= BEGIN EXPORTS Foo END",
		"Sample DEFINITIONS ::= BEGIN EXPORTS ALL, Foo; END",
		"Sample DEFINITIONS ::= BEGIN EXPORTS Foo,; END",
		"Sample DEFINITIONS ::= BEGIN IMPORTS Foo FROM; END",
		"Sample DEFINITIONS ::= BEGIN IMPORTS FROM Other; END",
		"Sample DEFINITIONS ::= BEGIN IMPORTS Foo FROM Other END",
		"Sample DEFINITIONS ::= BEGIN IMPORTS Foo FROM Other WITH KIN; END",
		"Sample DEFINITIONS ::= BEGIN IMPORTS Foo FROM Other WITH; END",
		"Sample DEFINITIONS ::= BEGIN IMPORTS Foo FROM Other; EXPORTS ALL; END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= END",
		"Sample DEFINITIONS ::= BEGIN foo ::= BOOLEAN END",
		"Sample DEFINITIONS ::= BEGIN Foo BOOLEAN END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= OCTET END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER { } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER { low } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER { low(1), } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= Other. END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= Other.thing END",
		"Sample DEFINITIONS ::= BEGIN flag ::= TRUE END",
		"Sample DEFINITIONS ::= BEGIN flag BOOLEAN ::= END",
		"Sample DEFINITIONS ::= BEGIN flag BOOLEAN TRUE END",
		"Sample DEFINITIONS ::= BEGIN BOOLEAN ::= TRUE END",
		"Sample DEFINITIONS ::= BEGIN v Foo ::= { 1, } END",
		"Sample DEFINITIONS ::= BEGIN v Foo ::= { , 1 } END",
		"Sample DEFINITIONS ::= BEGIN v Foo ::= { 1 END",
		"Sample DEFINITIONS ::= BEGIN v Foo ::= circle : END",
		"Sample DEFINITIONS ::= BEGIN F ::= P (WITH COMPONENTS { }) END",
		"Sample DEFINITIONS ::= BEGIN F ::= P (WITH COMPONENTS { ... }) END",
		"Sample DEFINITIONS ::= BEGIN F ::= P (WITH COMPONENT) END",
		"Sample DEFINITIONS ::= BEGIN A ::= [] INTEGER END",
		"Sample DEFINITIONS ::= BEGIN A ::= [0] END",
		"Sample DEFINITIONS ::= BEGIN A ::= [0] IMPLICIT END",
		"Sample DEFINITIONS ::= BEGIN A ::= [UNIVERSAL] INTEGER END",
		"Sample DEFINITIONS ::= BEGIN A ::= [0 IMPLICIT INTEGER END",
		"Sample DEFINITIONS ::= BEGIN A ::= [-1] INTEGER END",
		// X.680 23.3's "CONTAINING Value" form of an OctetStringValue.
		// It is given up so that "(CONTAINING Type)" can be the contents
		// constraint, which is what specifications write; see
		// lib/review.md.
		"Sample DEFINITIONS ::= BEGIN v OCTET STRING ::= CONTAINING w END",
		"Sample DEFINITIONS ::= BEGIN A ::= SEQUENCE { ...! } END",
		"Sample DEFINITIONS ::= BEGIN A ::= circle < END",
		"Sample DEFINITIONS ::= BEGIN Small INTEGER ::= { } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= CHOICE { } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= ENUMERATED { } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= SEQUENCE { a INTEGER, } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= SEQUENCE { INTEGER } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= SEQUENCE OF END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= CHOICE { a INTEGER OPTIONAL } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= ENUMERATED { a BOOLEAN } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= SEQUENCE { a INTEGER ..., } END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER () END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER (1..) END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER (..10) END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER (, ...) END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER (1 | ) END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= SIZE (1) END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER (MAX..1) END",
		"Sample DEFINITIONS ::= BEGIN Foo ::= INTEGER (1..MIN) END",
	}
	for _, src := range cases {
		if _, err := ParseModules([]byte(src)); err == nil {
			t.Errorf("expected error for input %q, got none", src)
		}
	}
}
