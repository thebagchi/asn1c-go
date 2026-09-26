// The tests here are in the package rather than beside it, because Lex takes an *asn1SymType
// and goyacc generates that type unexported. go.md permits the internal form
// when the thing under test cannot be named from outside, and asks that the
// file say why; this is that.
package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

// tok pairs a token with the string lexeme the lexer captured for it, which
// is enough to assert on in most of the tests below.
type tok struct {
	token int
	str   string
}

// lexAll runs the Lexer over src until EOF (token 0) and returns every
// token produced along with the raw lexeme text.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func lexAll(t *testing.T, src string) []tok {
	t.Helper()

	lexer := NewLexer([]byte(src))

	var toks []tok

	for {
		var lval asn1SymType

		token := lexer.Lex(&lval)
		if token == 0 {
			break
		}

		toks = append(toks, tok{token: token, str: string(lval.TypeString)})
	}

	if errs := lexer.Errors(); len(errs) != 0 {
		t.Fatalf("unexpected lexer errors: %v", errs)
	}

	return toks
}

// TestLexKeywords checks LexKeywords.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexKeywords(t *testing.T) {
	toks := lexAll(t, "BOOLEAN INTEGER SEQUENCE OF OPTIONAL DEFAULT")

	want := []int{TOK_BOOLEAN, TOK_INTEGER, TOK_SEQUENCE, TOK_OF, TOK_OPTIONAL, TOK_DEFAULT}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}

	for i, w := range want {
		if toks[i].token != w {
			t.Errorf(
				"token %d: got %d, want %d (%q)",
				i,
				toks[i].token,
				w,
				toks[i].str,
			)
		}
	}
}

// TestLexIdentifiersAndTypeReferences checks LexIdentifiersAndTypeReferences.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexIdentifiersAndTypeReferences(t *testing.T) {
	toks := lexAll(t, "myValue MyType another-value Another-Type")

	want := []struct {
		token int
		str   string
	}{
		{TOK_IDENT, "myValue"},
		{TOK_TYPEREF, "MyType"},
		{TOK_IDENT, "another-value"},
		{TOK_TYPEREF, "Another-Type"},
	}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}

	for i, w := range want {
		if toks[i].token != w.token || toks[i].str != w.str {
			t.Errorf(
				"token %d: got {%d %q}, want {%d %q}",
				i,
				toks[i].token,
				toks[i].str,
				w.token,
				w.str,
			)
		}
	}
}

// TestLexNumbers checks LexNumbers.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexNumbers(t *testing.T) {
	lexer := NewLexer([]byte("0 42 3.14 6.022e23"))

	var lval asn1SymType
	if token := lexer.Lex(&lval); TOK_NUM != token {
		t.Fatalf("got token %d, want TOK_NUM", token)
	} else if lval.TypeNumber != 0 {
		t.Errorf("got num %v, want 0", lval.TypeNumber)
	}

	lval = asn1SymType{}
	if token := lexer.Lex(&lval); TOK_NUM != token {
		t.Fatalf("got token %d, want TOK_NUM", token)
	} else if lval.TypeNumber != 42 {
		t.Errorf("got num %v, want 42", lval.TypeNumber)
	}

	lval = asn1SymType{}
	if token := lexer.Lex(&lval); TOK_REALNUM != token {
		t.Fatalf("got token %d, want TOK_REALNUM", token)
	} else if lval.TypeNumber != 3.14 {
		t.Errorf("got real %v, want 3.14", lval.TypeNumber)
	}

	lval = asn1SymType{}
	if token := lexer.Lex(&lval); TOK_REALNUM != token {
		t.Fatalf("got token %d, want TOK_REALNUM", token)
	} else if string(lval.TypeString) != "6.022e23" {
		t.Errorf("got str %q, want 6.022e23", lval.TypeString)
	}

	lval = asn1SymType{}
	if token := lexer.Lex(&lval); token != 0 {
		t.Fatalf("got token %d, want EOF", token)
	}
}

// TestLexStrings checks LexStrings.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexStrings(t *testing.T) {
	toks := lexAll(t, `'1010'B '1A2B'H "hello ""world"""`)

	want := []struct {
		token int
		str   string
	}{
		{TOK_BSTR, "'1010'B"},
		{TOK_HSTR, "'1A2B'H"},
		{TOK_CSTR, `"hello ""world"""`},
	}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}

	for i, w := range want {
		if toks[i].token != w.token || toks[i].str != w.str {
			t.Errorf(
				"token %d: got {%d %q}, want {%d %q}",
				i,
				toks[i].token,
				toks[i].str,
				w.token,
				w.str,
			)
		}
	}
}

// TestLexFieldReferences checks LexFieldReferences.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexFieldReferences(t *testing.T) {
	toks := lexAll(t, "&Type &value")

	want := []tok{
		{TOK_TYPEFIELDREF, "&Type"},
		{TOK_VALUEFIELDREF, "&value"},
	}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}

	for i, w := range want {
		if toks[i] != w {
			t.Errorf("token %d: got %+v, want %+v", i, toks[i], w)
		}
	}
}

// TestLexPunctuation checks LexPunctuation. Every punctuation item has a
// token of its own, the single characters included, so that no rule in
// grammar.y is written with a quoted character. The order they are
// matched in is what most of this checks: the longest item that fits wins,
// so "..." is not two items and "::=" is not a colon.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-09-24 16:58: single characters have tokens rather than runes
func TestLexPunctuation(t *testing.T) {
	toks := lexAll(t, `::= ... .. [[ ]] </ /> { } ( ) , ; @ | ! ^ < >`)

	want := []tok{
		{TOK_ASSIGNMENT, "::="},
		{TOK_ELLIPSIS, "..."},
		{TOK_RANGE_SEPARATOR, ".."},
		{TOK_LEFT_VERSION_BRACKETS, "[["},
		{TOK_RIGHT_VERSION_BRACKETS, "]]"},
		{TOK_XML_END_TAG_START, "</"},
		{TOK_XML_SINGLE_TAG_END, "/>"},
		{TOK_LEFT_CURLY_BRACKET, "{"},
		{TOK_RIGHT_CURLY_BRACKET, "}"},
		{TOK_LEFT_PARENTHESIS, "("},
		{TOK_RIGHT_PARENTHESIS, ")"},
		{TOK_COMMA, ","},
		{TOK_SEMICOLON, ";"},
		{TOK_COMMERCIAL_AT, "@"},
		{TOK_VERTICAL_LINE, "|"},
		{TOK_EXCLAMATION_MARK, "!"},
		{TOK_CIRCUMFLEX_ACCENT, "^"},
		{TOK_LESS_THAN_SIGN, "<"},
		// The greater-than sign has no token: nothing in ASN.1 uses one
		// on its own, so it stays the rune it is and reaches the parser
		// as an error, which is what it is.
		{int('>'), ">"},
	}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}

	for i, w := range want {
		if toks[i] != w {
			t.Errorf("token %d: got %+v, want %+v", i, toks[i], w)
		}
	}
}

// TestLexComments checks LexComments.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexComments(t *testing.T) {
	toks := lexAll(t, "-- a line comment\nBOOLEAN /* a\nblock comment */ INTEGER")

	want := []int{TOK_BOOLEAN, TOK_INTEGER}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}

	for i, w := range want {
		if toks[i].token != w {
			t.Errorf("token %d: got %d, want %d", i, toks[i].token, w)
		}
	}
}

// TestLexSampleFiles checks LexSampleFiles.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexSampleFiles(t *testing.T) {
	files, err := filepath.Glob("testdata/asn1c/*-ok.asn1")
	if err != nil {
		t.Fatalf("failed to glob sample files: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected at least one sample file")
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}

			data = RemoveComments(data)

			toks := lexAll(t, string(data))
			if len(toks) == 0 {
				t.Fatalf("expected at least one token from %s", file)
			}

			if toks[0].token != TOK_TYPEREF {
				t.Errorf(
					"first token of %s: got %d, want TOK_TYPEREF",
					file, toks[0].token,
				)
			}
			// Every ASN.1 module body must be closed with END; this holds
			// regardless of what leading comments/definitions look like.
			if last := toks[len(toks)-1]; TOK_END != last.token {
				t.Errorf(
					"last token of %s: got %d, want TOK_END",
					file,
					last.token,
				)
			}
		})
	}
}

// TestLexerError checks LexerError.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestLexerError(t *testing.T) {
	lexer := NewLexer([]byte("BOOLEAN"))
	lexer.Error("boom")
	lexer.Error("bang")

	errs := lexer.Errors()
	if len(errs) != 2 {
		t.Fatalf("got %d errors, want 2: %v", len(errs), errs)
	}
}

// TestLexEncodingPrefix checks LexEncodingPrefix. The brackets a tag is
// written in are the brackets an encoding prefix is written in, and a
// syntax list's optional groups use them too, so what this asserts is the
// three-way telling apart: only a prefix becomes one token.
//
// Revisions:
//   - 2026-09-25 10:12: initial creation
func TestLexEncodingPrefix(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []tok
	}{
		{
			name: "an instruction is one token",
			src:  "[XER:ATTRIBUTE] INTEGER",
			want: []tok{
				{TOK_ENCODING_PREFIX, "[XER:ATTRIBUTE]"},
				{TOK_INTEGER, "INTEGER"},
			},
		},
		{
			name: "an instruction needs no encoding reference",
			src:  "[USE-NIL]",
			want: []tok{{TOK_ENCODING_PREFIX, "[USE-NIL]"}},
		},
		{
			name: "a tag is left to the grammar",
			src:  "[APPLICATION 7]",
			want: []tok{
				{TOK_LEFT_SQUARE_BRACKET, "["},
				{TOK_APPLICATION, "APPLICATION"},
				{TOK_NUM, "7"},
				{TOK_RIGHT_SQUARE_BRACKET, "]"},
			},
		},
		{
			name: "a tag number qualified by its module is a tag",
			src:  "[Mod.tag]",
			want: []tok{
				{TOK_LEFT_SQUARE_BRACKET, "["},
				{TOK_TYPEREF, "Mod"},
				{TOK_FULL_STOP, "."},
				{TOK_IDENT, "tag"},
				{TOK_RIGHT_SQUARE_BRACKET, "]"},
			},
		},
		{
			name: "a tag with an encoding reference is a tag",
			src:  "[ENC: 0]",
			want: []tok{
				{TOK_LEFT_SQUARE_BRACKET, "["},
				{TOK_TYPEREF, "ENC"},
				{TOK_COLON, ":"},
				{TOK_NUM, "0"},
				{TOK_RIGHT_SQUARE_BRACKET, "]"},
			},
		},
		{
			name: "version brackets are not a prefix",
			src:  "[[",
			want: []tok{{TOK_LEFT_VERSION_BRACKETS, "[["}},
		},
		{
			name: "a syntax list keeps its own brackets",
			src:  "WITH SYNTAX { [VALUE &value] }",
			want: []tok{
				{TOK_WITH, "WITH"},
				{TOK_SYNTAX, "SYNTAX"},
				{TOK_LEFT_CURLY_BRACKET, "{"},
				{TOK_LEFT_SQUARE_BRACKET, "["},
				{TOK_TYPEREF, "VALUE"},
				{TOK_VALUEFIELDREF, "&value"},
				{TOK_RIGHT_SQUARE_BRACKET, "]"},
				{TOK_RIGHT_CURLY_BRACKET, "}"},
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			toks := lexAll(t, item.src)
			if len(toks) != len(item.want) {
				t.Fatalf(
					"got %d tokens, want %d: %+v",
					len(toks), len(item.want), toks,
				)
			}

			for index, want := range item.want {
				if toks[index] == want {
					continue
				}

				t.Errorf(
					"token %d: got %+v, want %+v",
					index, toks[index], want,
				)
			}
		})
	}
}
