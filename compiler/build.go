package compiler

import (
	"github.com/thebagchi/asn1c-go/ast"
)

// The nodes a grammar action builds often enough that spelling them out in
// the action would bury what the rule is doing. Each one is a shape
// proto/ast.proto declares; they are here rather than in grammar.y so that
// the actions stay a line or two each and read as the notation they match.

// _Builtin returns a type X.680 defines itself, named by the words it is
// spelt with.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Builtin(name string) *ast.Type {
	return &ast.Type{
		Kind: &ast.Type_Builtin{
			Builtin: &ast.BuiltinType{Name: name},
		},
	}
}

// _Referenced returns a type named by a reference, with the module it came
// from where the reference named one.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Referenced(module, name string) *ast.Type {
	return &ast.Type{
		Kind: &ast.Type_Reference{
			Reference: &ast.ReferenceType{Module: module, Name: name},
		},
	}
}

// _Parameterized returns X.683's parameterized value or object, a name with
// actual parameters after it.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Parameterized(module, name string, arguments []*ast.Setting) *ast.Value {
	return &ast.Value{
		Kind: &ast.Value_Parameterized{
			Parameterized: &ast.Parameterized{
				Module:    module,
				Name:      name,
				Arguments: arguments,
			},
		},
	}
}

// _Named returns a value written as a name: an INTEGER's named number, an
// ENUMERATED's item, or a reference to a value defined elsewhere. Which of
// the three it is depends on the type the value was written for, which no
// parser reads.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Named(name string) *ast.Value {
	return &ast.Value{Kind: &ast.Value_Named{Named: name}}
}

// _Number returns a value written as a number, kept as the lexeme rather
// than parsed, because an ASN.1 INTEGER has no bound and parsing one here
// would quietly round it.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Number(text string) *ast.Value {
	return &ast.Value{Kind: &ast.Value_Number{Number: text}}
}

// _Special returns one of the values X.680 spells with a word - NULL, MIN,
// MAX, PLUS-INFINITY and the rest.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Special(text string) *ast.Value {
	return &ast.Value{Kind: &ast.Value_Special{Special: text}}
}

// _Element returns one entry of a braced value, which is a run of values
// written side by side.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Element(values []*ast.Value) *ast.Element {
	return &ast.Element{
		Kind: &ast.Element_Values{
			Values: &ast.Values{Values: values},
		},
	}
}

// _Braced returns a value written between braces, as its entries.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Braced(elements []*ast.Element) *ast.Value {
	return &ast.Value{
		Kind: &ast.Value_Braced{
			Braced: &ast.Braced{Elements: elements},
		},
	}
}

// _Set returns an element set holding one value, which is how a single value
// stands in a constraint.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Set(value *ast.Value) *ast.ElementSet {
	return &ast.ElementSet{Kind: &ast.ElementSet_Value{Value: value}}
}

// _Operands returns one of the element sets that combine two others - a
// union, an intersection or an EXCEPT.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Operands(left, right *ast.ElementSet) *ast.Operands {
	return &ast.Operands{Operands: []*ast.ElementSet{left, right}}
}

// _Component returns a named component of a SEQUENCE, SET or CHOICE, or an
// item of an ENUMERATED.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _Component(named *ast.NamedComponent) *ast.Component {
	return &ast.Component{Kind: &ast.Component_Named{Named: named}}
}

// _TypeSetting returns a setting that is a type, and _ValueSetting one that
// is a value. X.681 lets a setting be either and says the governor decides,
// so both shapes are kept and the resolver reads them.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _TypeSetting(node *ast.Type) *ast.Setting {
	return &ast.Setting{Kind: &ast.Setting_Type{Type: node}}
}

// _ValueSetting returns a setting that is a value. See _TypeSetting.
//
// Revisions:
//   - 2026-09-26 02:14: initial creation
func _ValueSetting(node *ast.Value) *ast.Setting {
	return &ast.Setting{Kind: &ast.Setting_Value{Value: node}}
}

// _Constructed returns a SEQUENCE, SET, CHOICE or ENUMERATED, whose entries
// are kept flat with the extension markers among them; see Component.
//
// Revisions:
//   - 2026-09-26 02:31: initial creation
func _Constructed(name string, components []*ast.Component) *ast.Type {
	return &ast.Type{
		Kind: &ast.Type_Builtin{
			Builtin: &ast.BuiltinType{Name: name, Components: components},
		},
	}
}

// _Collection returns a SEQUENCE OF or a SET OF. X.680's NamedType form lets
// the repeated element carry a name, which is what label is.
//
// Revisions:
//   - 2026-09-26 02:31: initial creation
func _Collection(name string, element *ast.Type, label string) *ast.Type {
	return &ast.Type{
		Kind: &ast.Type_Builtin{
			Builtin: &ast.BuiltinType{
				Name:        name,
				Element:     element,
				ElementName: label,
			},
		},
	}
}

// Endpoint is one end of a value range while the rule that builds the range
// is still reading it: the value, and whether the "<" that excludes it was
// written. It is not a node of its own in the schema, because X.680 does not
// give it one - Range carries both ends and both flags.
type Endpoint struct {
	Value *ast.Value
	Open  bool
}

// _Field returns a type reached through a class or an object - "FOO.&Type",
// "obj.&value". Which of X.681's five forms it is depends on what the field
// holds, which the class says and no parser can.
//
// Revisions:
//   - 2026-09-26 03:02: initial creation
func _Field(module, reference string, field []string) *ast.Type {
	return &ast.Type{
		Kind: &ast.Type_Field{
			Field: &ast.FieldType{
				Module:    module,
				Reference: reference,
				Field:     field,
			},
		},
	}
}

// _FieldSetting returns one field of an object written in a class's own
// syntax: the field being set, and what it is set to.
//
// Revisions:
//   - 2026-09-26 03:41: initial creation
func _FieldSetting(field string, setting *ast.Setting) *ast.Element {
	return &ast.Element{
		Kind: &ast.Element_Setting{
			Setting: &ast.FieldSetting{
				Field: field,
				Value: setting,
			},
		},
	}
}
