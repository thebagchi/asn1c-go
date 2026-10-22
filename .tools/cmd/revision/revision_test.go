package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHit matches a file, a parent directory, and a note.
// A comma inside the note is not a separator.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func TestHit(t *testing.T) {
	rows := []struct {
		name string
		file string
		cell string
		want bool
	}{
		{
			name: "file",
			file: "lib/per/string.go",
			cell: "lib/per/string.go",
			want: true,
		},
		{
			name: "directory",
			file: "lib/per/string.go",
			cell: "lib/bitbuffer, lib/per",
			want: true,
		},
		{
			name: "note",
			file: ".tools/cmd/convention/declare.go",
			cell: ".tools/cmd/convention (declare.go new, checks.go)",
			want: true,
		},
		{
			name: "miss",
			file: "lib/per/string.go",
			cell: "lib/bitbuffer",
			want: false,
		},
	}

	for _, row := range rows {
		t.Run(
			row.name,
			func(t *testing.T) {
				got := _Hit(
					row.file,
					row.cell,
				)
				if got != row.want {
					t.Fatalf(
						"hit = %v, want %v",
						got,
						row.want,
					)
				}
			},
		)
	}
}

// TestRegression_RevisionRow fails when the new row is absent or omits a Go file.
// A directory in Files covers the file under it.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func TestRegression_RevisionRow(t *testing.T) {
	dir := _Repo(
		t,
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"revision.md",
		),
		"| When | Commit | Files | Intent |\n"+
			"| --- | --- | --- | --- |\n"+
			"| 2026-10-21 20:00 | — | keep.txt | Add the first row. |\n",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"lib",
			"per",
			"string.go",
		),
		"package per\n\nfunc Read() {\n\treturn\n}\n",
	)
	_Commit(
		t,
		dir,
		"revision.md",
		"lib/per/string.go",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"lib",
			"per",
			"string.go",
		),
		"package per\n\nfunc Read() {\n\treturn\n}\n\nfunc Write() {\n\treturn\n}\n",
	)

	absent := _Must(
		t,
		dir,
	)
	if !strings.Contains(
		absent,
		"no new row",
	) {
		t.Fatalf(
			"absent = %s",
			absent,
		)
	}

	_Append(
		t,
		filepath.Join(
			dir,
			"revision.md",
		),
		"| 2026-10-21 20:58 | — | lib/bitbuffer | Record the wrong directory. |\n",
	)

	miss := _Must(
		t,
		dir,
	)
	if !strings.Contains(
		miss,
		"omits lib/per/string.go",
	) {
		t.Fatalf(
			"miss = %s",
			miss,
		)
	}

	_Append(
		t,
		filepath.Join(
			dir,
			"revision.md",
		),
		"| 2026-10-21 20:58 | — | lib/per | Record the edit. |\n",
	)

	got := _Must(
		t,
		dir,
	)
	if strings.Contains(
		got,
		"error:",
	) {
		t.Fatalf(
			"clean = %s",
			got,
		)
	}
}

// _Must runs the check and returns the combined output.
// A non-zero status is allowed. A git failure is not.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Must(
	t *testing.T,
	dir string,
) string {
	t.Helper()

	problems, err := _Problems(
		dir,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	return strings.Join(
		problems,
		"\n",
	)
}

// _Repo returns a new git repository in a temporary directory.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Repo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	_Git(
		t,
		dir,
		"init",
	)

	return dir
}

// _Commit records the named files.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Commit(
	t *testing.T,
	dir string,
	files ...string,
) {
	t.Helper()

	args := append(
		[]string{"add", "--"},
		files...,
	)
	_Git(
		t,
		dir,
		args...,
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
}

// _Append adds text to the end of a file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Append(
	t *testing.T,
	path string,
	text string,
) {
	t.Helper()

	file, err := os.OpenFile(
		path,
		os.O_APPEND|os.O_WRONLY,
		0o644,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	_, err = file.WriteString(
		text,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	err = file.Close()
	if err != nil {
		t.Fatal(
			err,
		)
	}
}

// _Write creates one file and its parent directory.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Write(
	t *testing.T,
	path string,
	text string,
) {
	t.Helper()

	err := os.MkdirAll(
		filepath.Dir(
			path,
		),
		0o755,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	err = os.WriteFile(
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
//   - 2026-10-21 20:58: initial creation
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
