package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegression_Call reports the function that calls the named function.
// A function that does not call it stays out of the answer.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func TestRegression_Call(t *testing.T) {
	var (
		dir = _Module(
			t,
		)
		lines, err = _Edges(
			&_Opt{
				dir:      dir,
				name:     "Foo",
				patterns: []string{"."},
			},
		)
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	text := strings.Join(
		lines,
		"\n",
	)
	if !strings.Contains(
		text,
		".Bar calls",
	) || !strings.Contains(
		text,
		".Foo",
	) {
		t.Fatalf(
			"edges = %s",
			text,
		)
	}

	if strings.Contains(
		text,
		".Other calls",
	) {
		t.Fatalf(
			"edges = %s",
			text,
		)
	}
}

// TestRegression_ChangedCall reports a caller of a function defined in the diff.
// The caller can sit in a file the diff does not touch.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func TestRegression_ChangedCall(t *testing.T) {
	dir := _Module(
		t,
	)
	_Git(
		t,
		dir,
		"init",
	)
	_Git(
		t,
		dir,
		"add",
		"--",
		".",
	)
	_Git(
		t,
		dir,
		"-c",
		"user.email=dev@example.com",
		"-c",
		"user.name=dev",
		"commit",
		"-m",
		"init",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"a.go",
		),
		"package p\n\n// Foo stays the callee.\nfunc Foo() {\n\treturn\n}\n",
	)

	lines, err := _Edges(
		&_Opt{
			dir:     dir,
			changed: true,
		},
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	text := strings.Join(
		lines,
		"\n",
	)
	if !strings.Contains(
		text,
		"b.go:",
	) || !strings.Contains(
		text,
		".Bar calls",
	) {
		t.Fatalf(
			"edges = %s",
			text,
		)
	}
}

// _Module writes a two-file module. b.go calls Foo. Other does not.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Module(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	_Write(
		t,
		filepath.Join(
			dir,
			"go.mod",
		),
		"module example.com/graph\n\ngo 1.26\n",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"a.go",
		),
		"package p\n\nfunc Foo() {\n\treturn\n}\n",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"b.go",
		),
		"package p\n\nfunc Bar() {\n\tFoo()\n}\n\nfunc Other() {\n\treturn\n}\n",
	)

	return dir
}

// _Write creates one file.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Write(
	t *testing.T,
	path string,
	text string,
) {
	t.Helper()

	err := os.WriteFile(
		path,
		[]byte(text),
		0o644,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
}

// _Git runs git in dir and fails the test on a non-zero status.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Git(
	t *testing.T,
	dir string,
	args ...string,
) {
	t.Helper()

	cmd := exec.Command(
		"git",
		args...,
	)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"git %s: %v\n%s",
			args,
			err,
			out,
		)
	}
}
