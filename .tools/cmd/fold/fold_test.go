package main

import (
	"go/format"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	GO_MOD    = "module example.com/m\n\ngo 1.26\n"
	DIR_MODE  = 0o750
	FILE_MODE = 0o600
	SOURCE    = "m.go"
	HEAD_M    = "package m\n\nfunc g(a ...int) {}\n\n"
	HEAD_SUB  = "package sub\n\nfunc g(a ...int) {}\n\n"
)

// _All returns every golden case.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _All() []_Case {
	return slices.Concat(
		CASES_CALL,
		CASES_PARAMS,
		CASES_LITERAL,
		CASES_KEEP,
	)
}

// _Module writes a go.mod and the named files into a new temp directory.
// It returns the directory with symbolic links resolved.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Module(
	t *testing.T,
	files map[string]string,
) string {
	t.Helper()

	dir, err := filepath.EvalSymlinks(
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	_Put(
		t,
		filepath.Join(
			dir,
			"go.mod",
		),
		[]byte(GO_MOD),
	)

	for name, text := range files {
		_Put(
			t,
			filepath.Join(
				dir,
				name,
			),
			[]byte(text),
		)
	}

	return dir
}

// _Put writes one file and makes its directory.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Put(
	t *testing.T,
	path string,
	data []byte,
) {
	t.Helper()

	err := os.MkdirAll(
		filepath.Dir(
			path,
		),
		DIR_MODE,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	err = os.WriteFile(
		path,
		data,
		FILE_MODE,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
}

// _FoldTree runs Fold over every package of dir and fails the test on an error.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
//   - 2026-10-21 13:09: rename so the command can share this package
func _FoldTree(
	t *testing.T,
	dir string,
) map[string][]byte {
	t.Helper()

	out, err := Fold(
		dir,
		[]string{"./..."},
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	return out
}

// TestFold_Golden checks the folded source of each golden case.
// A case whose want equals its input must be absent from the result.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func TestFold_Golden(t *testing.T) {
	for _, item := range _All() {
		t.Run(
			item.name,
			func(t *testing.T) {
				var (
					dir = _Module(
						t,
						map[string]string{SOURCE: item.input},
					)
					out = _FoldTree(
						t,
						dir,
					)
					path = filepath.Join(
						dir,
						SOURCE,
					)
				)

				if item.input == item.want {
					if len(out) != 0 {
						t.Fatalf(
							"want no change, got %d file(s):\n%s",
							len(out),
							out[path],
						)
					}

					return
				}

				if string(out[path]) != item.want {
					t.Fatalf(
						"differs\n--- got ---\n%s\n--- want ---\n%s",
						out[path],
						item.want,
					)
				}
			},
		)
	}
}

// TestFold_Stable checks that folded source folds to itself.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func TestFold_Stable(t *testing.T) {
	for _, item := range _All() {
		t.Run(
			item.name,
			func(t *testing.T) {
				var (
					dir = _Module(
						t,
						map[string]string{SOURCE: item.want},
					)
					out = _FoldTree(
						t,
						dir,
					)
				)

				if len(out) != 0 {
					t.Fatalf(
						"folded source changes again:\n%s",
						out,
					)
				}
			},
		)
	}
}

// TestFold_WantFormatted checks that each wanted source is what gofmt prints.
// It also checks that want differs from input by newlines and trailing commas only.
// A wrong golden then fails here, and not in the tool.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func TestFold_WantFormatted(t *testing.T) {
	for _, item := range _All() {
		t.Run(
			item.name,
			func(t *testing.T) {
				got, err := format.Source(
					[]byte(item.want),
				)
				if err != nil {
					t.Fatal(
						err,
					)
				}

				if string(got) != item.want {
					t.Fatalf(
						"want is not gofmt-clean\n--- gofmt ---\n%s",
						got,
					)
				}

				_Same(
					t,
					[]byte(item.input),
					[]byte(item.want),
				)
			},
		)
	}
}

// TestFold_Paths checks that the keys are absolute and that an unchanged file is absent.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func TestFold_Paths(t *testing.T) {
	var (
		dir = _Module(
			t,
			map[string]string{
				"a.go":     HEAD_M + "func A() {\n\tg(1, 2)\n}\n",
				"b.go":     "package m\n\nfunc B() {\n\tg(1)\n}\n",
				"sub/c.go": HEAD_SUB + "func C() {\n\tg(1, 2)\n}\n",
			},
		)
		out = _FoldTree(
			t,
			dir,
		)
	)

	keys := make(
		[]string,
		0,
		len(out),
	)
	for key := range out {
		keys = append(
			keys,
			key,
		)
	}

	slices.Sort(
		keys,
	)

	want := []string{
		filepath.Join(
			dir,
			"a.go",
		),
		filepath.Join(
			dir,
			"sub",
			"c.go",
		),
	}
	if !slices.Equal(
		keys,
		want,
	) {
		t.Fatalf(
			"changed files: got %v, want %v",
			keys,
			want,
		)
	}
}

// TestFold_TestFile checks that a _test.go file is loaded and folded.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func TestFold_TestFile(t *testing.T) {
	var (
		dir = _Module(
			t,
			map[string]string{
				"m.go":      "package m\n\nfunc g(a ...int) {}\n",
				"m_test.go": "package m\n\nfunc Use() {\n\tg(1, 2)\n}\n",
			},
		)
		out = _FoldTree(
			t,
			dir,
		)
		path = filepath.Join(
			dir,
			"m_test.go",
		)
		want = "package m\n\nfunc Use() {\n\tg(\n\t\t1,\n\t\t2,\n\t)\n}\n"
	)

	if len(out) != 1 || string(out[path]) != want {
		t.Fatalf(
			"got %v, want only %s with:\n%s",
			out,
			path,
			want,
		)
	}
}

// TestFold_Comment checks that a comment inside a call survives the fold.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func TestFold_Comment(t *testing.T) {
	var (
		src = "package m\n\nfunc g(a ...int) {}\n\nfunc Use() {\n" +
			"\tg(1, // inside\n\t\t2)\n}\n"
		dir = _Module(
			t,
			map[string]string{SOURCE: src},
		)
		out = _FoldTree(
			t,
			dir,
		)
		got = out[filepath.Join(
			dir,
			SOURCE,
		)]
	)

	if !strings.Contains(
		string(got),
		"// inside",
	) {
		t.Fatalf(
			"comment lost:\n%s",
			got,
		)
	}

	_Same(
		t,
		[]byte(src),
		got,
	)
	_Clean(
		t,
		got,
	)
}

// _Same fails the test unless old and updated differ only by newlines and trailing commas.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Same(
	t *testing.T,
	old []byte,
	updated []byte,
) {
	t.Helper()

	var (
		before = _Tokens(
			t,
			old,
		)
		after = _Tokens(
			t,
			updated,
		)
	)

	if !slices.Equal(
		before,
		after,
	) {
		t.Fatalf(
			"tokens differ\n--- old ---\n%s\n--- new ---\n%s",
			strings.Join(
				before,
				" ",
			),
			strings.Join(
				after,
				" ",
			),
		)
	}
}

// _Clean fails the test unless gofmt leaves src as it is.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Clean(
	t *testing.T,
	src []byte,
) {
	t.Helper()

	got, err := format.Source(
		src,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	if string(got) != string(src) {
		t.Fatalf(
			"not gofmt-clean\n--- gofmt ---\n%s\n--- source ---\n%s",
			got,
			src,
		)
	}
}

// _Tokens returns the token stream of src, comments included.
// It drops each automatic semicolon.
// It drops each comma whose next token, comments aside, is ) or } or ].
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Tokens(
	t *testing.T,
	src []byte,
) []string {
	t.Helper()

	var (
		scan  scanner.Scanner
		items []string
		kinds []token.Token
	)

	var (
		set  = token.NewFileSet()
		file = set.AddFile(
			"x.go",
			set.Base(),
			len(src),
		)
	)
	scan.Init(
		file,
		src,
		func(
			pos token.Position,
			msg string,
		) {
			t.Errorf(
				"%s: %s",
				pos,
				msg,
			)
		},
		scanner.ScanComments,
	)

	for {
		_, kind, text := scan.Scan()
		if kind == token.EOF {
			break
		}

		if kind == token.SEMICOLON && text == "\n" {
			continue
		}

		kinds = append(
			kinds,
			kind,
		)
		items = append(
			items,
			kind.String()+" "+text,
		)
	}

	return _Trim(
		items,
		kinds,
	)
}

// _Trim removes each comma that sits before a closing token.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Trim(
	items []string,
	kinds []token.Token,
) []string {
	var out []string

	for idx, kind := range kinds {
		if kind == token.COMMA && _Closes(
			kinds[idx+1:],
		) {
			continue
		}

		out = append(
			out,
			items[idx],
		)
	}

	return out
}

// _Closes reports whether the first token of rest, comments aside, closes a list.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Closes(rest []token.Token) bool {
	for _, kind := range rest {
		switch kind {
		case token.COMMENT:
			continue
		case token.RPAREN:
			fallthrough
		case token.RBRACE:
			fallthrough
		case token.RBRACK:
			return true
		default:
			return false
		}
	}

	return false
}
