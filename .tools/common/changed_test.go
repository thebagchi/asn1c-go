package common_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

// TestChangedGo lists a modified Go file and an untracked Go file.
// A committed file that the work tree does not touch stays out.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func TestChangedGo(t *testing.T) {
	dir := _Repo(
		t,
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"old.go",
		),
		"package old\n",
	)
	_Commit(
		t,
		dir,
		"old.go",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"old.go",
		),
		"package old\n\nfunc Old() {\n\treturn\n}\n",
	)
	_Write(
		t,
		filepath.Join(
			dir,
			"new.go",
		),
		"package old\n",
	)

	got, err := common.ChangedGo(
		dir,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	want := []string{"new.go", "old.go"}
	if len(
		got,
	) != len(
		want,
	) {
		t.Fatalf(
			"files = %v",
			got,
		)
	}

	for i, file := range want {
		if got[i] != file {
			t.Fatalf(
				"files = %v",
				got,
			)
		}
	}
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

// _Commit records the named files as the first commit.
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

// _Write creates one file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
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
