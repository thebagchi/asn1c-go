package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	MODULE_PATH = "github.com/thebagchi/asn1c-go"
	GEN_DIR     = "gen"
)

// PACKAGES lists the repository directories that the property test copies.
// lib/bitbuffer imports lib/cpu, so the temp module holds both.
var (
	PACKAGES = []string{
		"lib/cpu",
		"lib/bitbuffer",
	}
)

// TestFold_Repository folds real code and checks what the contract promises.
// The code is a frozen copy of lib/cpu and lib/bitbuffer, taken before the tree was
// folded, in testdata/repo.
// The test puts it in a temp module that has the module path of this repository.
// It does not read the live tree, so folding the live tree cannot empty the test.
// Each folded file differs from the old one only by newlines and trailing commas.
// Each is gofmt-clean, and convention reports no call or literal.
// A second fold changes nothing, and the module still builds.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
//   - 2026-10-19 10:34: read the code from the frozen testdata/repo, not from lib/
func TestFold_Repository(t *testing.T) {
	if testing.Short() {
		t.Skip("skip the repository copy under -short")
	}

	_, err := exec.LookPath(
		"go",
	)
	if err != nil {
		t.Skip("go is not on PATH")
	}

	dir := _Module(
		t,
		nil,
	)
	_Put(
		t,
		filepath.Join(
			dir,
			"go.mod",
		),
		[]byte("module "+MODULE_PATH+"\n\ngo 1.26\n"),
	)

	for _, pkg := range PACKAGES {
		_Copy(
			t,
			filepath.Join(
				"testdata",
				"repo",
				filepath.FromSlash(pkg),
			),
			filepath.Join(
				dir,
				filepath.FromSlash(pkg),
			),
		)
	}

	before := _Findings(
		t,
		dir,
	)
	if before == 0 {
		t.Fatal("the copied code has no finding, so the test proves nothing")
	}

	out := _FoldTree(
		t,
		dir,
	)
	if len(out) == 0 {
		t.Fatal("fold changed no file")
	}

	_Check(
		t,
		dir,
		out,
	)
}

// _Check writes the folded files and checks the promises of the contract.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Check(
	t *testing.T,
	dir string,
	out map[string][]byte,
) {
	t.Helper()

	for path, data := range out {
		old, err := os.ReadFile(
			path,
		)
		if err != nil {
			t.Fatal(
				err,
			)
		}

		t.Run(
			strings.TrimPrefix(
				path,
				dir,
			),
			func(t *testing.T) {
				_Same(
					t,
					old,
					data,
				)
				_Clean(
					t,
					data,
				)
			},
		)
		_Put(
			t,
			path,
			data,
		)
	}

	count := _Findings(
		t,
		dir,
	)
	if count != 0 {
		t.Errorf(
			"convention still reports %d call or literal finding(s)",
			count,
		)
	}

	again := _FoldTree(
		t,
		dir,
	)
	if len(again) != 0 {
		t.Errorf(
			"a second fold changes %d file(s)",
			len(again),
		)
	}

	_Build(
		t,
		dir,
	)
}

// _Copy copies the .go and .s files below from into to, and skips each gen directory.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Copy(
	t *testing.T,
	from string,
	to string,
) {
	t.Helper()

	err := filepath.WalkDir(
		from,
		func(
			path string,
			entry fs.DirEntry,
			err error,
		) error {
			if err != nil {
				return err
			}

			if entry.IsDir() && entry.Name() == GEN_DIR {
				return filepath.SkipDir
			}

			ext := filepath.Ext(
				path,
			)
			if entry.IsDir() || (ext != ".go" && ext != ".s") {
				return nil
			}

			data, err := os.ReadFile(
				path,
			)
			if err != nil {
				return err
			}

			rel, err := filepath.Rel(
				from,
				path,
			)
			if err != nil {
				return err
			}

			_Put(
				t,
				filepath.Join(
					to,
					rel,
				),
				data,
			)

			return nil
		},
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
}

// _Findings counts the call and literal findings of every package under dir.
// The convention command is package main, so this test runs that command.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
//   - 2026-10-21 13:09: run the convention command
func _Findings(
	t *testing.T,
	dir string,
) int {
	t.Helper()

	cmd := exec.Command(
		"go",
		"run",
		_Convention(
			t,
		),
		"-dir",
		dir,
		"-check=call,literal",
		"./...",
	)

	cmd.Env = append(
		os.Environ(),
		"GOWORK=off",
		"GOFLAGS=",
	)

	var (
		out, err = cmd.CombinedOutput()
		count    = _CountFindings(
			string(
				out,
			),
		)
	)

	if err != nil && count == 0 {
		t.Fatalf(
			"convention: %v\n%s",
			err,
			out,
		)
	}

	return count
}

// _CountFindings counts the call and literal lines in text.
//
// Revisions:
//   - 2026-10-21 13:09: initial creation
func _CountFindings(text string) int {
	count := 0

	for _, line := range strings.Split(
		text,
		"\n",
	) {
		if _CallOrLiteral(
			line,
		) {
			count++
		}
	}

	return count
}

// _Convention returns the absolute path of the convention command.
//
// Revisions:
//   - 2026-10-21 13:09: initial creation
func _Convention(t *testing.T) string {
	t.Helper()

	path, err := filepath.Abs(
		filepath.Join(
			"..",
			"convention",
		),
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	return path
}

// _CallOrLiteral reports whether line is one call or literal finding.
//
// Revisions:
//   - 2026-10-21 13:09: initial creation
func _CallOrLiteral(line string) bool {
	return strings.Contains(
		line,
		": error: call:",
	) || strings.Contains(
		line,
		": error: literal:",
	)
}

// _Build compiles every package of dir, tests included, and runs no test.
//
// Revisions:
//   - 2026-10-19 10:25: initial creation
func _Build(
	t *testing.T,
	dir string,
) {
	t.Helper()

	for _, args := range [][]string{
		{"build", "./..."},
		{"test", "-count=1", "-run", "^$", "./..."},
	} {
		cmd := exec.Command(
			"go",
			args...,
		)
		cmd.Dir = dir

		cmd.Env = append(
			os.Environ(),
			"GOWORK=off",
			"GOFLAGS=",
		)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf(
				"go %s: %v\n%s",
				strings.Join(
					args,
					" ",
				),
				err,
				out,
			)
		}
	}
}
