package compiler

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thebagchi/asn1c-go/ast"
)

// Streaming counterparts of the validation regexes in constants.go. Those
// are anchored with both ^ and $ because they validate a whole lexeme; the
// ones below only anchor with ^ so they can find the next token at the
// current position of a longer input stream.
var (
	// A byte order mark is whitespace for this purpose: a module that
	// opens with one is still a module, and nothing in ASN.1 gives it a
	// meaning. Seven of the modules under testdata/ begin with one.
	RE_LEX_WHITESPACE   = regexp.MustCompile(`^(\x{FEFF}|[\s])+`)
	RE_LEX_LINE_COMMENT = regexp.MustCompile(`^--.*?(--|\n|$)`)
	RE_LEX_BSTRING      = regexp.MustCompile(`^'[01\s]*'B`)
	RE_LEX_HSTRING      = regexp.MustCompile(`^'[0-9A-Fa-f\s]*'H`)
	RE_LEX_CSTRING      = regexp.MustCompile(`^"([^"]|"")*"`)
	RE_LEX_REAL_NUMBER  = regexp.MustCompile(
		`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`,
	)
	RE_LEX_TYPE_FIELD_REF  = regexp.MustCompile(`^&[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)*`)
	RE_LEX_VALUE_FIELD_REF = regexp.MustCompile(
		`^&[a-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*`,
	)
	RE_LEX_NAME = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*`)
	// TYPE_TOKENS is the reserved words a Type may begin with. Only those: an
	// element set is written between the same braces and its operators are
	// reserved words too, so a word that may follow a typereference there -
	// EXCEPT, UNION, INTERSECTION, SIZE - must not be in here or an element set
	// would be read as an object.
	// VALUE_TOKENS is the reserved words a braced value may hold. Every
	// other one written between braces belongs to a class's syntax.
	VALUE_TOKENS = map[int]bool{
		TOK_TRUE:           true,
		TOK_FALSE:          true,
		TOK_NULL:           true,
		TOK_PLUS_INFINITY:  true,
		TOK_MINUS_INFINITY: true,
		TOK_NOT_A_NUMBER:   true,
	}

	// KEYWORD_SET is every reserved word by token, which tokens.go holds by
	// lexeme. Reading it back the other way is what tells a word from a
	// name once the lexeme is gone.
	KEYWORD_SET = _Keywords()

	TYPE_TOKENS = map[int]bool{
		TOK_BOOLEAN:          true,
		TOK_INTEGER:          true,
		TOK_ENUMERATED:       true,
		TOK_REAL:             true,
		TOK_BIT:              true,
		TOK_OCTET:            true,
		TOK_NULL:             true,
		TOK_SEQUENCE:         true,
		TOK_SET:              true,
		TOK_CHOICE:           true,
		TOK_OBJECT:           true,
		TOK_RELATIVE_OID:     true,
		TOK_OID_IRI:          true,
		TOK_RELATIVE_OID_IRI: true,
		TOK_EMBEDDED:         true,
		TOK_EXTERNAL:         true,
		TOK_CHARACTER:        true,
		TOK_UTC_TIME:         true,
		TOK_GENERALIZED_TIME: true,
		TOK_INSTANCE:         true,
	}
)

// _Keywords returns every reserved word's token.
//
// Revisions:
//   - 2026-09-25 14:02: initial creation
func _Keywords() map[int]bool {
	keywords := make(map[int]bool, len(KEYWORD_TOKENS))
	for _, token := range KEYWORD_TOKENS {
		keywords[token] = true
	}

	return keywords
}

// Lexer scans ASN.1 source text into tokens. asn1SymType and the asn1Lexer
// interface (Lex(lval *asn1SymType) int and Error(s string)) are generated
// by goyacc from grammar.y (see grammar.go); Lexer implements that
// interface directly, with no adapter required.
type Lexer struct {
	src    []byte
	pos    int
	line   int
	col    int
	errors []string

	// last is the token Lex returned before this one. _LexBraces needs
	// it: a class body and a syntax list are written with the same braces
	// as a value, and are told from one by the word before them.
	last int

	// prior is the token before last, which _LexInstructions needs: an
	// encoding control section opens with two tokens, not one.
	prior int

	// third is the token before prior, which _LexBraces needs: an object
	// assignment is told from an object set's by the case of the name
	// three tokens back, and that is as far back as anything here looks.
	third int

	// syntax marks the braces after WITH SYNTAX. X.681 writes the optional
	// groups of a syntax list in square brackets, which are the brackets a
	// tag and an encoding prefix are written in, and only where the lexer
	// is says which of the three is meant. A syntax list holds no braces of
	// its own, so the one that opens it and the one that closes it are a
	// pair and no depth has to be counted.
	syntax bool

	// scout marks the Lexer _Group runs over a brace group to measure it.
	// One of those must not take a group of its own, or measuring the
	// outer one would measure the inner one for ever.
	scout bool

	// Result is set by the grammar's actions (see grammar.y) once a rule
	// successfully matches. It's how the parser hands a result back to Go
	// code, since asn1Parse itself only returns a pass/fail int.
	Result []*ast.Module
}

// ParseModules parses one or more back-to-back ASN.1 modules recognized by
// the current grammar (grammar.y) - the X.680 module header, the exports
// and imports its body opens with, and the type and value assignments that
// follow, over every built-in type X.680 defines, with constraints, with
// the values written between braces, with the parameterization of X.683
// and with the information object class definitions of X.681 - returning
// the parsed Modules on success. It will grow to cover more of the ASN.1 module
// syntax as grammar.y grows.
//
// The errors the Lexer collected are checked as well as the parse's own
// result, because a grammar action that finds a rule matched but said
// something X.680 does not allow reports it that way: asn1Parse still
// returns success, and without this the finding would be recorded and
// then dropped.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-09-24 09:41: the header's optional clauses are recognized
//   - 2026-09-24 10:18: errors reported by grammar actions fail the parse
func ParseModules(src []byte) ([]*ast.Module, error) {
	lexer := NewLexer(src)
	if asn1Parse(lexer) != 0 || len(lexer.Errors()) > 0 {
		return nil, fmt.Errorf("asn1: %s", strings.Join(lexer.Errors(), "; "))
	}

	return lexer.Result, nil
}

// NewLexer returns a Lexer over src, positioned at its first token.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func NewLexer(src []byte) *Lexer {
	return &Lexer{src: src, pos: 0, line: 1, col: 1}
}

// Lex implements the asn1Lexer interface generated by goyacc from
// grammar.y (see grammar.go), letting *Lexer be passed directly to
// asn1Parse.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (l *Lexer) Lex(lval *asn1SymType) int {
	l._Skip()

	rest := l._Remaining()
	if len(rest) == 0 {
		return 0 // EOF
	}

	lval.LINE, lval.COLUMN = INT(l.line), INT(l.col)

	scanners := []func([]byte, *asn1SymType) (int, bool){
		l._LexString,
		l._LexXMLValue,
		l._LexInstructions,
		l._LexAtBrace,
		l._LexAssignedIdent,
		l._LexPrefix,
		l._LexBraces,
		l._LexPunctuation,
		l._LexFieldRef,
		l._LexNumber,
		l._LexName,
	}

	for _, scan := range scanners {
		if token, ok := scan(rest, lval); ok {
			l._Track(token)

			return token
		}
	}

	// Single-character punctuation is returned as its own rune value, the
	// usual goyacc convention for literal character tokens.
	r, size := utf8.DecodeRune(rest)
	lval.TypeString = STR(string(r))

	l._Advance(size)
	l._Track(int(r))

	return int(r)
}

// Error implements the asn1Lexer interface generated by goyacc from
// grammar.y. It is called by the generated parser on syntax errors.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (l *Lexer) Error(s string) {
	l.errors = append(l.errors, fmt.Sprintf("line %d, col %d: %s", l.line, l.col, s))
}

// Errors returns every error reported through Error.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (l *Lexer) Errors() []string {
	return l.errors
}

// _Track records the token just returned, and whether the lexer is now
// inside the braces of a syntax list.
//
// Revisions:
//   - 2026-09-25 09:31: initial creation
func (l *Lexer) _Track(token int) {
	switch {
	case token == TOK_LEFT_CURLY_BRACKET && l.last == TOK_SYNTAX:
		l.syntax = true

	case token == TOK_RIGHT_CURLY_BRACKET && l.syntax:
		l.syntax = false
	}

	l.third, l.prior, l.last = l.prior, l.last, token
}

// _Remaining returns the source the lexer has not consumed yet.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (l *Lexer) _Remaining() []byte {
	return l.src[l.pos:]
}

// _Advance consumes n bytes, keeping the line and column the next token will
// be reported at.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (l *Lexer) _Advance(n int) {
	for _, b := range l.src[l.pos : l.pos+n] {
		if b == '\n' {
			l.line++
			l.col = 1
		} else {
			l.col++
		}
	}

	l.pos += n
}

// _Skip consumes whitespace and comments preceding the next token.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (l *Lexer) _Skip() {
	skippable := []*regexp.Regexp{
		RE_LEX_WHITESPACE,
		RE_LEX_LINE_COMMENT,
	}

	for {
		rest := l._Remaining()

		taken := _Block(rest)

		if taken == 0 {
			for _, pattern := range skippable {
				if loc := pattern.FindIndex(rest); loc != nil {
					taken = loc[1]

					break
				}
			}
		}

		if taken == 0 {
			return
		}

		l._Advance(taken)
	}
}

// _Block measures a block comment, returning zero where one does not begin.
//
// X.680 12.6.4 nests them: a comment opened inside a comment must be closed
// before the outer one is, so "/* a /* b */ c */" is one comment and not two
// with "c */" between them. No regular expression counts, which is why this
// is written out - the depth is the whole of it.
//
// An unclosed comment runs to the end of the input, which is what X.680
// 12.6.4 says happens and leaves the syntax error where the module stopped
// making sense rather than at the comment.
//
// Revisions:
//   - 2026-09-25 12:06: initial creation
func _Block(rest []byte) int {
	if !bytes.HasPrefix(rest, []byte(BLOCK_COMMENT_OPEN)) {
		return 0
	}

	depth, index := 0, 0

	for index < len(rest) {
		switch {
		case bytes.HasPrefix(rest[index:], []byte(BLOCK_COMMENT_OPEN)):
			depth++
			index += len(BLOCK_COMMENT_OPEN)

		case bytes.HasPrefix(rest[index:], []byte(BLOCK_COMMENT_CLOSE)):
			depth--
			index += len(BLOCK_COMMENT_CLOSE)

			if depth == 0 {
				return index
			}

		default:
			index++
		}
	}

	return len(rest)
}

// _LexString scans a binary, hexadecimal or character string literal. It reports whether it
// matched.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Lex
func (l *Lexer) _LexString(rest []byte, lval *asn1SymType) (int, bool) {
	if loc := RE_LEX_BSTRING.FindIndex(rest); loc != nil {
		lval.TypeString = STR(rest[:loc[1]])
		l._Advance(loc[1])

		return TOK_BSTR, true
	}

	if loc := RE_LEX_HSTRING.FindIndex(rest); loc != nil {
		lval.TypeString = STR(rest[:loc[1]])
		l._Advance(loc[1])

		return TOK_HSTR, true
	}

	if loc := RE_LEX_CSTRING.FindIndex(rest); loc != nil {
		lval.TypeString = STR(rest[:loc[1]])
		l._Advance(loc[1])

		return TOK_CSTR, true
	}

	return 0, false
}

// _LexBraces returns a whole balanced brace group as one token when what
// stands inside it cannot be a value. It reports whether it matched.
//
// X.681 writes its information objects between the same braces that X.680
// writes values between, and which one a module meant is decided by the
// class the object belongs to - which a parser has not read. The two
// notations are not merely hard to tell apart: a run of settings written
// side by side makes "NAME {" both a parameterized type and two settings,
// and no grammar resolves that (see lib/review.md). So a group that
// cannot be a value is taken whole, for the pass that knows the class.
//
// The test _Group applies is sound in the direction that matters: what it
// takes really cannot be a value. What it lets through may still be an
// object written in a notation that happens to look like one, which is a
// miss rather than a mistake.
//
// Revisions:
//   - 2026-09-24 15:33: initial creation
func (l *Lexer) _LexBraces(rest []byte, lval *asn1SymType) (int, bool) {
	if l.scout {
		return 0, false
	}

	// A class body and a syntax list are written with the same braces and
	// do hold field references. Both follow a reserved word that nothing
	// else is followed by, so the word before the brace tells them apart.
	if l.last == TOK_CLASS || l.last == TOK_SYNTAX {
		return 0, false
	}

	if len(rest) == 0 || rest[0] != LEFT_CURLY_BRACKET[0] {
		return 0, false
	}

	// A group that opens with a field reference is X.681's default object
	// syntax, which the grammar does parse - see the pattern section at
	// the foot of grammar.y - so it is left for it.
	if l._Opens(rest) == TOK_VALUEFIELDREF || l._Opens(rest) == TOK_TYPEFIELDREF {
		return 0, false
	}

	group := l._Group(rest)
	if group == nil {
		return 0, false
	}

	// A group holding a bare name is an object set, but only where one
	// can stand: after an opening parenthesis, which is X.682's table
	// constraint, and after a brace or a comma, which is an actual
	// parameter -
	//
	//	ProtocolIE-Container { {ResetIEs} }
	//
	// which is how every application protocol under testdata/3gpp names
	// the objects a message may carry.
	//
	// The union and intersection signs are here for the same reason: an
	// object set is written as its objects with "|" between them, so every
	// object after the first follows one. DEFAULT is here because X.681
	// lets a value set field carry one.
	//
	// Nowhere else. A bare name is ordinary inside a component list, a
	// CONSTRAINED BY, or a formal parameter list, and each of those
	// follows a token that is none of these.
	//
	// A group carrying an extension marker is taken in the same three
	// places and for the same reason. X.681 lets an actual parameter be an
	// object set, so "AlgorithmIdentifier{ALGORITHM, {...}}" passes one
	// that is nothing but a marker, and X.680's braced values never hold a
	// marker at all - but an object set assignment's own braces do, and
	// those follow the class reference rather than any of these three
	// tokens, so they stay where the grammar reads them.
	opens := l.last == TOK_LEFT_PARENTHESIS ||
		l.last == TOK_LEFT_CURLY_BRACKET ||
		l.last == TOK_COMMA ||
		l.last == TOK_VERTICAL_LINE ||
		l.last == TOK_CIRCUMFLEX_ACCENT ||
		l.last == TOK_DEFAULT

	set := (group.Names || group.Marked || group.Union) && opens

	// A group that names something no braced value has room for: a word of
	// some class's syntax, or a typereference standing on its own. Either
	// says the notation is the class's rather than X.680's.
	group.Written = group.Words || group.Names

	// An object written where only an object or a braced value may stand.
	// X.681 assigns one as "objectreference DefinedObjectClass ::=", which
	// is a lower-case name, an upper-case one and then the assignment - and
	// X.680 assigns a value with the very same three, because a class is a
	// type as far as the tokens go. What is between the braces settles it:
	// a value holds values, so a word or a bare typereference there is the
	// class's notation - "{ID 2}", "{ERRORS {refuse} SYNCHRONOUS TRUE}".
	//
	// An object set and a value set are not this shape - both are assigned
	// to an upper-case name - so neither is taken here.
	assigned := l.third == TOK_IDENT &&
		l.prior == TOK_TYPEREF &&
		l.last == TOK_ASSIGNMENT

	// An object whose first setting is a type, which a class may ask for -
	// "ct-Data CONTENT-TYPE ::= {OCTET STRING IDENTIFIED BY id-data}". It
	// is taken only straight after "::=", because that is where an object
	// assignment writes it and a formal parameter list, which opens with a
	// type too, never stands: that one follows the name being assigned.
	object := group.Typed && l.last == TOK_ASSIGNMENT

	// The four shapes that say these braces hold an object or an object
	// set, which the pass that has the class reads, rather than a value,
	// which the grammar reads here.
	kept := group.Object || set || object || (assigned && group.Written)
	if !kept {
		return 0, false
	}

	lval.TypeString = STR(rest[:group.Length])
	l._Advance(group.Length)

	return TOK_BRACES, true
}

// Group is what _Group found in a brace group: how far it runs, and the
// two shapes that say what the group cannot be.
type Group struct {
	Length  int
	Object  bool
	Names   bool
	Marked  bool
	Typed   bool
	Words   bool
	Union   bool
	Written bool
}

// _Opens returns the token after the brace that rest opens with, which
// says what kind of group it is without measuring the whole of it.
//
// Revisions:
//   - 2026-09-24 16:14: initial creation
func (l *Lexer) _Opens(rest []byte) int {
	scout := NewLexer(rest)
	scout.scout = true
	lval := asn1SymType{}

	scout.Lex(&lval)

	return scout.Lex(&lval)
}

// _Group measures the balanced brace group at the front of rest and
// reports whether what it holds cannot be a value.
//
// Two shapes say so, and both are read only at the group's own level, so
// that a nested group is judged on its own when the parser reaches it:
//
//   - a field reference standing on its own, which no value notation
//     contains - one after a full stop is part of a type, "FOO.&id"; and
//   - a typereference followed by a name, which no value and no element
//     set can have either, since neither admits a bare typereference next
//     to anything but a full stop.
//
// It also reports whether the group holds a bare typereference at all,
// which a value has no room for but an element set does. That one says
// nothing on its own; _LexBraces reads it only where an element set
// cannot stand.
//
// The group is measured by lexing it with a second Lexer rather than by
// counting bytes, so that a brace inside a comment or a string is not
// counted. That rescans a nested group once for each level it sits under,
// which a module is small enough not to notice.
//
// Revisions:
//   - 2026-09-24 15:33: initial creation
func (l *Lexer) _Group(rest []byte) *Group {
	scout := NewLexer(rest)
	scout.scout = true
	lval := asn1SymType{}
	group := &Group{}
	depth, previous := 0, 0

	for {
		token := scout.Lex(&lval)
		if token == 0 {
			return nil
		}

		// What a token says is read before the braces are counted,
		// because the one that says it may be the closing brace.
		if depth == 1 {
			group._Shape(previous, token)
		}

		if token == TOK_LEFT_CURLY_BRACKET {
			depth++
			previous = 0

			continue
		}

		if token == TOK_RIGHT_CURLY_BRACKET {
			depth--

			if depth == 0 {
				group.Length = scout.pos

				return group
			}

			previous = 0

			continue
		}

		if depth == 1 {
			previous = token
		}
	}
}

// _Shape records what token says about the group it stands at the top
// level of, having come after previous.
//
// Revisions:
//   - 2026-09-24 17:20: initial creation
func (g *Group) _Shape(previous, token int) {
	// A typereference that no full stop follows is a name standing on its
	// own, which a value has no room for but an element set does.
	if previous == TOK_TYPEREF && token != TOK_FULL_STOP {
		g.Names = true
	}

	// A field reference says the group is an object, but only where it
	// stands on its own. One after a full stop is part of a type -
	// "FOO.&id" names a field of a class - and those appear in component
	// lists, which are values' territory.
	field := token == TOK_TYPEFIELDREF || token == TOK_VALUEFIELDREF
	if field && previous != TOK_FULL_STOP {
		g.Object = true
	}

	// One after a full stop is a name of the class's, "FOO.&id", and where
	// a group is an object set it is X.681's ObjectSetFromObjects - the
	// objects a field of some other object holds, "{Operations.&Errors}".
	// A value has no room for it either way, so it counts with the names.
	if field && previous == TOK_FULL_STOP {
		g.Names = true
	}

	// A union sign, which separates an element set's alternatives. A braced
	// value separates its entries with commas and has no use for one, so a
	// group carrying it is a value set or an object set - which is what a
	// class field's DEFAULT may be, "&Critical BOOLEAN DEFAULT {TRUE | FALSE}".
	if token == TOK_VERTICAL_LINE {
		g.Union = true
	}

	// An extension marker, which an element set may be written with and a
	// value may not: X.680's braced values hold values, and "..." is not
	// one. So a group that carries one is a value set or an object set.
	if token == TOK_ELLIPSIS {
		g.Marked = true
	}

	// A word of a class's own syntax. X.680's braced values hold values, and
	// the only reserved words a value is written with are the six below, so
	// any other one at the top of a group is a word the class declared -
	// "{SYNTAX GeneralizedTime}", "{ERRORS {refuse} SYNCHRONOUS TRUE}".
	if _Word(token) {
		g.Words = true
	}

	// A built-in type opening the group. Everything else written between
	// braces opens with something else - a component list with a component
	// name, a braced value with an identifier or a value, an object set
	// with the brace of its first object - so a type standing first says an
	// object written in its class's own syntax, as in
	// "{OCTET STRING IDENTIFIED BY id-data}" for the class that reads
	// "&Type IDENTIFIED BY &id".
	//
	// Only first, and only where _LexBraces then allows it. A component
	// list names a type after every component name, and a formal parameter
	// list opens with one - "{INTEGER : lowerBound, ...}".
	if previous == 0 && TYPE_TOKENS[token] {
		g.Typed = true
	}

	// Two names side by side, which no value and no element set has. A
	// built-in type counts as the second of them: a class whose syntax
	// reads "TYPE &Value" is written "TYPE INTEGER", and INTEGER is a
	// reserved word rather than a typereference, so without this a group
	// whose settings are all types and numbers has nothing to mark it.
	named := token == TOK_TYPEREF || token == TOK_IDENT || TYPE_TOKENS[token]
	if previous == TOK_TYPEREF && named {
		g.Object = true
	}
}

// _LexXMLValue returns a whole XML typed value as one token. It reports
// whether it matched.
//
// X.680 clause 16.2 writes an XML value assignment as a valuereference,
// "::=" and the value - with no type between the name and the assignment,
// which is what an ordinary value assignment has there. So the two tokens
// before this one say an XML value is what follows, and the lexer can
// stop reading ASN.1 for the length of it.
//
// It has to stop. The text inside an XML element is not ASN.1: X.680
// gives it its own lexical items - an "xmlbstring" is bits with no
// quotes around them, an "xmlcstring" is arbitrary text in which space
// counts - and an ASN.1 lexer reading "<A>0101</A>" would find a number
// that is not one. The element is therefore taken whole, and what it
// holds is read by the pass that knows the type it was written for, the
// same way every other value is (see lib/review.md).
//
// Revisions:
//   - 2026-09-24 18:12: initial creation
func (l *Lexer) _LexXMLValue(rest []byte, lval *asn1SymType) (int, bool) {
	if l.scout {
		return 0, false
	}

	if l.prior != TOK_IDENT || l.last != TOK_ASSIGNMENT {
		return 0, false
	}

	if len(rest) == 0 || rest[0] != LESS_THAN_SIGN[0] {
		return 0, false
	}

	length := l._Element(rest)
	if length == 0 {
		return 0, false
	}

	lval.TypeString = STR(rest[:length])
	l._Advance(length)

	return TOK_XML_VALUE, true
}

// _Element measures the XML element at the front of rest, counting tags
// rather than characters so that an element holding others is measured
// whole. It returns zero for anything that does not close.
//
// Revisions:
//   - 2026-09-24 18:12: initial creation
func (l *Lexer) _Element(rest []byte) int {
	opening, closing := LESS_THAN_SIGN[0], GREATER_THAN_SIGN[0]
	solidus := SOLIDUS[0]
	depth, at := 0, 0
	seen := false

	for at < len(rest) {
		if rest[at] != opening {
			at++

			continue
		}

		end := bytes.IndexByte(rest[at:], closing)
		if end < 0 {
			return 0
		}

		end += at

		switch {
		case rest[at+1] == solidus:
			depth--
		case rest[end-1] == solidus:
			// An empty element, which opens and closes at once.
		default:
			depth++
		}

		seen = true
		at = end + 1

		if seen && depth == 0 {
			return at
		}
	}

	return 0
}

// _LexInstructions returns the body of an encoding control section as one
// token. It reports whether it matched.
//
// X.680 clause 54 says what opens such a section - the words
// ENCODING-CONTROL and the encoding it speaks for - and then hands the
// rest to that encoding: the section holds an
// EncodingInstructionAssignmentList, which X.693 defines for XER, X.697
// for JER, and X.680 does not define at all. There is no grammar here to
// write, so the body is kept as the text it is, ending where the next
// section or the module does.
//
// Revisions:
//   - 2026-09-24 17:48: initial creation
func (l *Lexer) _LexInstructions(rest []byte, lval *asn1SymType) (int, bool) {
	if l.scout {
		return 0, false
	}

	// A section opens with the two words, so the token before last is what
	// says one has just begun.
	if l.prior != TOK_ENCODING_CONTROL || l.last != TOK_TYPEREF {
		return 0, false
	}

	length := l._Instructions(rest)
	if length == 0 {
		return 0, false
	}

	lval.TypeString = STR(rest[:length])
	l._Advance(length)

	return TOK_INSTRUCTIONS_BODY, true
}

// _Instructions measures the body of an encoding control section, which
// runs to whichever of END and the next ENCODING-CONTROL comes first.
// Neither may appear inside one, so no nesting has to be tracked.
//
// Revisions:
//   - 2026-09-24 17:48: initial creation
func (l *Lexer) _Instructions(rest []byte) int {
	scout := NewLexer(rest)
	scout.scout = true
	lval := asn1SymType{}
	length := 0

	for {
		token := scout.Lex(&lval)
		if token == 0 || token == TOK_END || token == TOK_ENCODING_CONTROL {
			return length
		}

		length = scout.pos
	}
}

// _LexAssignedIdent returns the valuereference that names a module's object
// identifier in an IMPORTS clause. It reports whether it matched.
//
// X.680 lets a GlobalModuleReference carry its object identifier as a
// DefinedValue rather than as arcs in braces, and clause 11 NOTE says what
// that costs: in
//
//	Name              FROM InformationFramework informationFramework
//	UniqueIdentifier  FROM SelectedAttributeTypes selectedAttributeTypes
//
// "informationFramework" is the first module's assigned identifier, and in
//
//	FROM InformationFramework name, attribute FROM SelectedAttributeTypes
//
// "name" is the first symbol of the next list. The two are the same token in
// the same place, and X.680 resolves it in prose rather than in the syntax -
// so no rule can, and a grammar that tried would have to reduce an empty
// assigned identifier before reading the token that decides.
//
// What decides is the token after: a symbol is followed by a comma or by
// FROM, and an assigned identifier by anything else - a semicolon, WITH, or
// the first symbol of the next list. That is one token past this one, which
// is one too many for the parser and none at all for a lexer that is already
// standing here.
//
// Revisions:
//   - 2026-09-25 12:41: initial creation
func (l *Lexer) _LexAssignedIdent(rest []byte, lval *asn1SymType) (int, bool) {
	if l.scout {
		return 0, false
	}

	// Only ever between a module reference and whatever ends the import.
	if l.prior != TOK_FROM || l.last != TOK_TYPEREF {
		return 0, false
	}

	name := RE_LEX_NAME.Find(rest)
	if name == nil || !_Reference(name) {
		return 0, false
	}

	if _Symbol(_Next(rest[len(name):])) {
		return 0, false
	}

	lval.TypeString = STR(name)
	l._Advance(len(name))

	return TOK_ASSIGNED_IDENT, true
}

// _Reference reports whether a lexeme is a valuereference: a name that opens
// in lower case and is not one of ASN.1's own words.
//
// Revisions:
//   - 2026-09-25 12:41: initial creation
func _Reference(name []byte) bool {
	if len(name) == 0 || name[0] < 'a' || name[0] > 'z' {
		return false
	}

	_, reserved := KEYWORD_TOKENS[string(name)]

	return !reserved
}

// _Symbol reports whether the token after a name says the name was a symbol
// of the next import rather than an assigned identifier.
//
// Revisions:
//   - 2026-09-25 12:41: initial creation
func _Symbol(token int) bool {
	return token == TOK_COMMA || token == TOK_FROM || token == TOK_LEFT_CURLY_BRACKET
}

// _Next returns the first token of rest, or zero where rest holds none.
//
// Revisions:
//   - 2026-09-25 12:41: initial creation
func _Next(rest []byte) int {
	scout := NewLexer(rest)
	scout.scout = true
	lval := asn1SymType{}

	return scout.Lex(&lval)
}

// _LexPrefix returns X.680 31's encoding prefix as one token, the brackets
// included. It reports whether it matched.
//
// An encoding prefix and a tag are written between the same brackets, and
// what separates them is the part no grammar here can hold: a tag's
// content is a class and a number, where a prefix's is an encoding
// instruction, and X.680 leaves that to whichever encoding-rules
// standard the reference names - X.691 defines its own, X.693 another.
// There is no production for it to be written from.
//
// So the bracket group is measured and read the only way it can be: a
// content that is a tag is left for the grammar, and anything else is an
// instruction and is kept whole for the pass that has the encoding rules.
// The decision needs no more than the group itself, which is why it can be
// made here at all.
//
// Revisions:
//   - 2026-09-25 09:12: initial creation
func (l *Lexer) _LexPrefix(rest []byte, lval *asn1SymType) (int, bool) {
	if l.scout || l.syntax {
		return 0, false
	}

	if len(rest) == 0 || rest[0] != LEFT_SQUARE_BRACKET[0] {
		return 0, false
	}

	// Version brackets are two of these, and they open a component list
	// rather than anything written around a type.
	if len(rest) > 1 && rest[1] == LEFT_SQUARE_BRACKET[0] {
		return 0, false
	}

	length, prefix := l._Bracket(rest)
	if length == 0 || !prefix {
		return 0, false
	}

	lval.TypeString = STR(rest[:length])
	l._Advance(length)

	return TOK_ENCODING_PREFIX, true
}

// _Bracket measures a bracket group and says whether its content is an
// encoding instruction. A length of zero means the group is not closed,
// which the grammar reports where it stands.
//
// Revisions:
//   - 2026-09-25 09:12: initial creation
func (l *Lexer) _Bracket(rest []byte) (int, bool) {
	scout := NewLexer(rest[len(LEFT_SQUARE_BRACKET):])
	scout.scout = true
	lval := asn1SymType{}

	var tokens []int

	for {
		token := scout.Lex(&lval)
		if token == 0 {
			return 0, false
		}

		if token == TOK_RIGHT_SQUARE_BRACKET {
			length := len(LEFT_SQUARE_BRACKET) + scout.pos

			return length, _Instruction(tokens)
		}

		tokens = append(tokens, token)
	}
}

// _Instruction reports whether the tokens between a pair of brackets spell
// an encoding instruction rather than a tag.
//
// Every encoding-rules standard names its instructions with a word -
// X.693 writes ATTRIBUTE, USE-NIL and BASE64, and X.696 its own - where a
// tag is a class and a number. So a group that opens with a word, once the
// encoding reference both may carry is set aside, is an instruction, and
// one that spells a tag is a tag whichever way it opens: X.680 lets a tag
// number be a valuereference the module it came from qualifies, which
// begins with a word too.
//
// Anything that is neither is left alone, so an empty group and a group
// holding a class and no number reach the grammar and are reported there.
//
// Revisions:
//   - 2026-09-25 09:44: initial creation
func _Instruction(tokens []int) bool {
	if _Tag(tokens) {
		return false
	}

	if len(tokens) > 1 && tokens[0] == TOK_TYPEREF && tokens[1] == TOK_COLON {
		tokens = tokens[2:]
	}

	return len(tokens) != 0 && tokens[0] == TOK_TYPEREF
}

// _Tag reports whether the tokens between a pair of brackets spell a tag.
//
// Revisions:
//   - 2026-09-25 09:12: initial creation
func _Tag(tokens []int) bool {
	if len(tokens) > 1 && tokens[0] == TOK_TYPEREF && tokens[1] == TOK_COLON {
		tokens = tokens[2:]
	}

	if len(tokens) > 0 && _Class(tokens[0]) {
		tokens = tokens[1:]
	}

	// X.680's ClassNumber: a number, a valuereference, or one the module it
	// came from qualifies.
	switch len(tokens) {
	case PLAIN_NUMBER_ITEMS:
		return tokens[0] == TOK_NUM || tokens[0] == TOK_IDENT

	case QUALIFIED_NUMBER_ITEMS:
		return tokens[0] == TOK_TYPEREF &&
			tokens[1] == TOK_FULL_STOP &&
			tokens[2] == TOK_IDENT
	}

	return false
}

// How many lexical items a tag number is written with: one on its own, and
// three where the module it came from qualifies it.
const (
	PLAIN_NUMBER_ITEMS     = 1
	QUALIFIED_NUMBER_ITEMS = 3
)

// _Word reports whether a token is a reserved word that no braced value is
// written with, which makes it a word of some class's own syntax.
//
// Revisions:
//   - 2026-09-25 14:02: initial creation
func _Word(token int) bool {
	if VALUE_TOKENS[token] {
		return false
	}

	return KEYWORD_SET[token]
}

// _Class reports whether a token is one of X.680's tag classes.
//
// Revisions:
//   - 2026-09-25 09:12: initial creation
func _Class(token int) bool {
	return token == TOK_UNIVERSAL ||
		token == TOK_APPLICATION ||
		token == TOK_PRIVATE
}

// _LexAtBrace returns a distinct token for the brace that opens X.682's
// at-notation, "{@id}". It reports whether it matched.
//
// A component relation constraint is written as one braced group after
// another, and the second brace cannot be told from a type's own by a
// parser: "Foo {" is a parameterized type as readily as it is the start
// of an at-notation. The "@" that always follows this one settles it, and
// a brace followed by an at sign occurs nowhere else in ASN.1, so the
// lexer gives that brace a token of its own and the grammar needs no
// lookahead at all.
//
// Revisions:
//   - 2026-09-24 16:14: initial creation
func (l *Lexer) _LexAtBrace(rest []byte, lval *asn1SymType) (int, bool) {
	if l.scout {
		return 0, false
	}

	if len(rest) == 0 || rest[0] != LEFT_CURLY_BRACKET[0] {
		return 0, false
	}

	if l._Opens(rest) != TOK_COMMERCIAL_AT {
		return 0, false
	}

	lval.TypeString = STR(LEFT_CURLY_BRACKET)
	l._Advance(len(LEFT_CURLY_BRACKET))

	return TOK_AT_BRACE, true
}

// _LexPunctuation scans a multi-character punctuation item. It reports whether it matched.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Lex
func (l *Lexer) _LexPunctuation(rest []byte, lval *asn1SymType) (int, bool) {
	for _, p := range PUNCTUATION_TOKENS {
		if !bytes.HasPrefix(rest, []byte(p.text)) {
			continue
		}

		if l.syntax && _Version(p.token) {
			continue
		}

		lval.TypeString = STR(p.text)
		l._Advance(len(p.text))

		return p.token, true
	}

	return 0, false
}

// _Version reports whether a token is one of the version brackets, which are
// two square brackets written together.
//
// Inside a syntax list they are not that. X.681 nests its optional groups, so
// a group that ends where the one around it ends is written "]]", and the
// longest item that fits is what the table above finds - which is the wrong
// item in the one place two brackets can meet without being a pair. A syntax
// list has no extension additions in it, so neither bracket is ever meant
// there and both are left to be read one at a time.
//
// Revisions:
//   - 2026-09-25 12:19: initial creation
func _Version(token int) bool {
	return token == TOK_LEFT_VERSION_BRACKETS || token == TOK_RIGHT_VERSION_BRACKETS
}

// _LexFieldRef scans a type or value field reference. It reports whether it matched.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Lex
func (l *Lexer) _LexFieldRef(rest []byte, lval *asn1SymType) (int, bool) {
	if loc := RE_LEX_TYPE_FIELD_REF.FindIndex(rest); loc != nil {
		lval.TypeString = STR(rest[:loc[1]])
		l._Advance(loc[1])

		return TOK_TYPEFIELDREF, true
	}

	if loc := RE_LEX_VALUE_FIELD_REF.FindIndex(rest); loc != nil {
		lval.TypeString = STR(rest[:loc[1]])
		l._Advance(loc[1])

		return TOK_VALUEFIELDREF, true
	}

	return 0, false
}

// _LexNumber scans a number, real or whole. It reports whether it matched.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Lex
func (l *Lexer) _LexNumber(rest []byte, lval *asn1SymType) (int, bool) {
	loc := RE_LEX_REAL_NUMBER.FindIndex(rest)
	if loc == nil {
		return 0, false
	}

	text := string(rest[:loc[1]])
	l._Advance(loc[1])

	lval.TypeString = STR(text)

	if strings.ContainsAny(text, ".eE") {
		if value, err := strconv.ParseFloat(text, 64); err == nil {
			lval.TypeNumber = NUMBER(value)
		}

		return TOK_REALNUM, true
	}

	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		lval.TypeNumber = NUMBER(value)
	}

	return TOK_NUM, true
}

// _LexName scans a keyword, type reference or identifier. It reports whether it matched.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Lex
func (l *Lexer) _LexName(rest []byte, lval *asn1SymType) (int, bool) {
	if loc := RE_LEX_NAME.FindIndex(rest); loc != nil {
		text := string(rest[:loc[1]])
		l._Advance(loc[1])

		lval.TypeString = STR(text)

		// Inside a syntax list every word is a literal the class declared,
		// not one of ASN.1's own: X.681 7.9 says a word is upper case and
		// hyphens, and says nothing about which ones are spoken for. So a
		// class may write CONTAINING or ERRORS as its own word, and the
		// grammar reads one rule rather than a list of every reserved word
		// a class might reach for.
		if l.syntax && RE_WORD.MatchString(text) {
			return TOK_TYPEREF, true
		}

		if token, ok := KEYWORD_TOKENS[text]; ok {
			return token, true
		}

		if RE_TYPE_REFERENCE.MatchString(text) {
			return TOK_TYPEREF, true
		}

		return TOK_IDENT, true
	}

	return 0, false
}
