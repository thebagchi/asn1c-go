package compiler

import (
	"fmt"
	"strings"

	"github.com/thebagchi/asn1c-go/ast"
)

// The module a setting is re-parsed inside. A setting is a type or a value
// and nothing says which, so it is tried as each in turn; whichever parses
// is what the module wrote. Both are the smallest module that can hold one.
const (
	TYPE_PROBE  = "P DEFINITIONS ::= BEGIN T ::= %s END"
	VALUE_PROBE = "P DEFINITIONS ::= BEGIN v T ::= %s END"
)

// Registry is the class table a resolution reads, and the stack of classes
// it is working under.
//
// The table is why this is a second pass rather than something the parser
// does as it goes. A class may be used before it is defined, and an
// imported one is defined in another module that the parser may not have
// reached - so no state accumulated during a parse can be relied on, and
// asn1c, which does accumulate it, needs a lexer hack for each place that
// bites. Here every module is parsed first and the table is complete
// before anything reads it.
//
// The stack is the other half. An object set holds objects, and a setting
// inside an object may be an object of another class, so which class
// governs is a property of where you are and not of the module. Push on
// the way in, pop on the way out.
type Registry struct {
	classes map[string]*ast.Class
	stack   []*ast.Class
	errors  []error
}

// NewRegistry returns a Registry over the classes every module defines.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func NewRegistry(modules []*ast.Module) *Registry {
	registry := &Registry{classes: map[string]*ast.Class{}}

	for _, module := range modules {
		for _, assignment := range module.GetAssignments() {
			if assignment.GetClass() == nil {
				continue
			}

			registry.classes[assignment.GetName()] = assignment.GetClass()
		}
	}

	return registry
}

// Resolve reads every information object a module wrote in its class's own
// syntax, turning the text the parser kept whole into the fields it sets.
//
// The parser cannot do this. X.681 lets a class declare the notation its
// objects are written in, so the same braces hold a different language per
// class, and no grammar covers all of them at once - see lib/review.md.
// What the parser does instead is keep the text, which is enough: the
// class's syntax list says what to expect, and this walks the two together.
//
// It returns the objects it could not read. A class that no module defines
// is the usual reason, which happens when a module imports one and only
// that module was parsed.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func (r *Registry) Resolve(modules []*ast.Module) []error {
	r.errors = nil

	for _, module := range modules {
		for _, assignment := range module.GetAssignments() {
			r._Assignment(assignment)
		}
	}

	return r.errors
}

// _Assignment resolves whatever objects one assignment holds, under the
// class it names.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func (r *Registry) _Assignment(assignment *ast.Assignment) {
	// The class an object or an object set is assigned under is written
	// where a value's type would be, because the two are the same tokens.
	governor := assignment.GetValue().GetType()
	if governor == nil {
		governor = assignment.GetValueSet().GetType()
	}

	class := r.classes[governor.GetReference().GetName()]
	if class == nil {
		return
	}

	r.stack = append(r.stack, class)
	defer func() { r.stack = r.stack[:len(r.stack)-1] }()

	r._Value(assignment.GetValue().GetValue())

	if set := assignment.GetValueSet().GetSet(); set != nil {
		r._Set(set.GetRoot())
		r._Set(set.GetAdditional())
	}
}

// _Set walks an element set, which is how an object set reaches here: each
// of its objects is a single value in the expression.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func (r *Registry) _Set(set *ast.ElementSet) {
	if set == nil {
		return
	}

	r._Value(set.GetValue())
	r._Set(set.GetAll())

	// The three that combine two others each carry their pair the same way.
	for _, operands := range []*ast.Operands{
		set.GetUnion(),
		set.GetIntersection(),
		set.GetExcept(),
	} {
		for _, operand := range operands.GetOperands() {
			r._Set(operand)
		}
	}
}

// _Value reads one value, if it is an object the class on top of the stack
// governs.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func (r *Registry) _Value(value *ast.Value) {
	opaque, ok := value.GetKind().(*ast.Value_Opaque)
	if !ok || len(r.stack) == 0 {
		return
	}

	class := r.stack[len(r.stack)-1]
	if len(class.GetSyntax()) == 0 {
		return
	}

	elements, err := _Match(class.GetSyntax(), opaque.Opaque)
	if err != nil {
		r.errors = append(r.errors, err)

		return
	}

	// The object now has the shape the default syntax already produced,
	// so nothing downstream has to know which notation it was written in.
	value.Kind = &ast.Value_Object{
		Object: &ast.Braced{
			Elements: elements,
		},
	}
}

// _Match walks a class's syntax and an object's text together, returning
// the field settings the object made.
//
// X.681 10.10 says how an optional group is decided: if what comes next
// could be the group's first item the group is there, and if it could not
// it is not. Its NOTE asks a class to make that first item a literal, and
// every class in testdata does, so that is what is looked at.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func _Match(syntax []*ast.SyntaxToken, text string) ([]*ast.Element, error) {
	words, err := _Words(text)
	if err != nil {
		return nil, err
	}

	elements, rest, err := _Walk(syntax, words, nil)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf(
			"object has %d lexical items its class does not account for",
			len(rest),
		)
	}

	return elements, nil
}

// _Walk matches one run of syntax tokens against the head of words,
// returning what it read and what is left.
//
// follow is where a setting stops when nothing in this run stops it, which
// is what an optional group needs: the setting that ends a group runs up to
// whatever the class writes after the group, and only the caller knows what
// that is.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
//   - 2026-09-24 22:34: a setting ending a group stops at what follows it
func _Walk(
	syntax []*ast.SyntaxToken,
	words []string,
	follow []string,
) ([]*ast.Element, []string, error) {
	var elements []*ast.Element

	for index, token := range syntax {
		switch {
		case token.GetGroup() != nil:
			group := token.GetGroup().GetTokens()
			if !_Opens(group, words) {
				continue
			}

			inner, rest, err := _Walk(
				group, words, _After(syntax[index+1:], follow),
			)
			if err != nil {
				return nil, nil, err
			}

			elements = append(elements, inner...)
			words = rest

		case token.GetLiteral() != "":
			if len(words) == 0 || words[0] != token.GetLiteral() {
				return nil, nil, fmt.Errorf(
					"expected %q in an object", token.GetLiteral(),
				)
			}

			words = words[1:]

		default:
			// A setting runs to the next literal the class names. Which
			// one that is depends on what the module wrote: a literal
			// that opens an optional group only stops the setting if
			// that group is there, so every literal that could come next
			// is looked for and the earliest of them wins.
			taken, rest := _Until(_After(syntax[index+1:], follow), words)
			if len(taken) == 0 {
				return nil, nil, fmt.Errorf(
					"nothing set for %q in an object", token.GetField(),
				)
			}

			elements = append(elements, _Setting(token.GetField(), taken))
			words = rest
		}
	}

	return elements, words, nil
}

// _After returns where a setting stops: the literals the rest of this run
// could write, or the caller's when this run writes none.
//
// Revisions:
//   - 2026-09-24 22:34: initial creation
func _After(syntax []*ast.SyntaxToken, follow []string) []string {
	stops := _Stops(syntax)
	if len(stops) == 0 {
		return follow
	}

	// A run that ends in an optional group can still fall through to what
	// the caller writes, so both are looked for.
	if _Optional(syntax) {
		return append(stops, follow...)
	}

	return stops
}

// _Optional reports whether a run of syntax tokens can be written entirely
// as nothing, which is true when every token in it is a group.
//
// Revisions:
//   - 2026-09-24 22:34: initial creation
func _Optional(syntax []*ast.SyntaxToken) bool {
	for _, token := range syntax {
		if token.GetGroup() == nil {
			return false
		}
	}

	return true
}

// _Opens reports whether words could begin the group, which is what X.681
// 10.10 asks in order to decide whether an optional group is present.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func _Opens(group []*ast.SyntaxToken, words []string) bool {
	opening := _Literal(group)
	if opening == "" || len(words) == 0 {
		return false
	}

	return words[0] == opening
}

// _Literal returns the first literal a run of syntax tokens names.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func _Literal(syntax []*ast.SyntaxToken) string {
	stops := _Stops(syntax)
	if len(stops) == 0 {
		return ""
	}

	return stops[0]
}

// _Stops returns every literal that could be the next one written, which is
// where a setting before them has to stop.
//
// There is more than one whenever an optional group comes next: the group's
// own opening literal if the module wrote the group, and whatever follows
// the group if it did not. Walking stops at the first literal that is not
// in a group, because nothing after a literal the module must write can
// come before it.
//
// Revisions:
//   - 2026-09-24 22:26: initial creation
func _Stops(syntax []*ast.SyntaxToken) []string {
	var stops []string

	for _, token := range syntax {
		if token.GetLiteral() != "" {
			return append(stops, token.GetLiteral())
		}

		if token.GetGroup() == nil {
			break
		}

		if opening := _Literal(token.GetGroup().GetTokens()); opening != "" {
			stops = append(stops, opening)
		}
	}

	return stops
}

// _Until splits words at the first one that is any of the given literals,
// or at the end when none of them was written.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func _Until(stops []string, words []string) ([]string, []string) {
	if len(stops) == 0 {
		return words, nil
	}

	for index, item := range words {
		for _, stop := range stops {
			if item == stop {
				return words[:index], words[index:]
			}
		}
	}

	return words, nil
}

// _Setting turns the words a field was set to back into a type or a value,
// by parsing them as each in turn. Whichever parses is what was written; if
// neither does, the text is kept as it stands so that nothing is lost.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func _Setting(field string, words []string) *ast.Element {
	text := strings.Join(words, " ")

	if modules, err := ParseModules(fmt.Appendf(nil, TYPE_PROBE, text)); err == nil {
		node := modules[0].GetAssignments()[0].GetType()

		return _FieldSetting(field, _TypeSetting(node))
	}

	if modules, err := ParseModules(fmt.Appendf(nil, VALUE_PROBE, text)); err == nil {
		node := modules[0].GetAssignments()[0].GetValue().GetValue()

		return _FieldSetting(field, _ValueSetting(node))
	}

	opaque := &ast.Value{
		Kind: &ast.Value_Opaque{
			Opaque: text,
		},
	}

	return _FieldSetting(field, _ValueSetting(opaque))
}

// _Words lexes the inside of an object's braces into the spelling of
// each lexical item, which is all a literal has to be compared against
// and all a setting has to be put back together from.
//
// Revisions:
//   - 2026-09-24 22:18: initial creation
func _Words(text string) ([]string, error) {
	body := strings.TrimSpace(text)
	if !strings.HasPrefix(body, LEFT_CURLY_BRACKET) ||
		!strings.HasSuffix(body, RIGHT_CURLY_BRACKET) {
		return nil, fmt.Errorf("an object is not written between braces")
	}

	lexer := NewLexer([]byte(body[1 : len(body)-1]))

	var words []string

	for {
		symbol := asn1SymType{}

		token := lexer.Lex(&symbol)
		if token == 0 {
			break
		}

		words = append(words, string(symbol.TypeString))
	}

	if errors := lexer.Errors(); len(errors) != 0 {
		return nil, fmt.Errorf("asn1: %s", strings.Join(errors, "; "))
	}

	return words, nil
}
