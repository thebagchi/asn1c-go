// Package main runs the convention checkers against fixtures.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"
)

// TestRevision reports a function that has no revision history.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func TestRevision(t *testing.T) {
	_RunFixture(
		t,
		REVISION,
		"revision",
	)
}

// TestLead reports an unexported name with no leading _.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func TestLead(t *testing.T) {
	_RunFixture(
		t,
		LEAD,
		"lead",
	)
}

// TestSnake reports a const or a package-level var that is not CAPITAL_SNAKE.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func TestSnake(t *testing.T) {
	_RunFixture(
		t,
		SNAKE,
		"snake",
	)
}

// TestFields reports a struct whose fields are not contiguous.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func TestFields(t *testing.T) {
	_RunFixture(
		t,
		FIELDS,
		"fields",
	)
}

// TestPointer reports a struct this module declares held by value.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func TestPointer(t *testing.T) {
	_RunFixture(
		t,
		POINTER,
		"pointer",
	)
}

// TestBanner reports a generated file whose banner is not the first line.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func TestBanner(t *testing.T) {
	_RunFixture(
		t,
		BANNER,
		"banner",
	)
}

// TestLiteral reports a struct literal that is not one field to a line.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func TestLiteral(t *testing.T) {
	_RunFixture(
		t,
		LITERAL,
		"literal",
	)
}

// TestCall reports a call or a signature that is not one item to a line.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func TestCall(t *testing.T) {
	_RunFixture(
		t,
		CALL,
		"call",
	)
}

// TestRegression_PointerFuncType reports a struct value in a function type
// that is not a declared function.
// A closure, an interface method, a named function type, and a function variable
// are parameters and results.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
//   - 2026-10-21 16:10: drop the claim that pointer reads only a FuncDecl
func TestRegression_PointerFuncType(t *testing.T) {
	_RunFixture(
		t,
		POINTER,
		"pointertype",
	)
}

// TestRegression_RevisionTime reports a first revision bullet with no time.
// The rule asks for the local time to the minute.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
//   - 2026-10-21 16:10: drop the claim that any initial-creation bullet passes
func TestRegression_RevisionTime(t *testing.T) {
	_RunFixture(
		t,
		REVISION,
		"revisiontime",
	)
}

// TestRegression_DeclareRun reports two short declarations in a row.
// A lone := stays as it is.
// A statement between two short declarations ends the run.
//
// Revisions:
//   - 2026-10-21 20:42: initial creation
func TestRegression_DeclareRun(t *testing.T) {
	_RunFixture(
		t,
		DECLARE,
		"declare",
	)
}

// TestRegression_OneLineBody reports a function body that stays on one line.
// The same rule applies to a closure.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
//   - 2026-10-21 16:10: drop the claim that no checker reads the brace line
func TestRegression_OneLineBody(t *testing.T) {
	_NeedCount(
		t,
		"bodyline",
		"more than one line",
		2,
	)
}

// TestRegression_DeferredClosure reports a deferred closure written on one line.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
//   - 2026-10-21 16:10: drop the claim that no checker reads a defer statement
func TestRegression_DeferredClosure(t *testing.T) {
	_NeedCount(
		t,
		"deferline",
		"deferred closure",
		1,
	)
}

// TestRegression_MutexOrder reports a mutex that sits below the data it guards.
// fields reports a blank line.
// fields does not read which field is the mutex.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
func TestRegression_MutexOrder(t *testing.T) {
	_NeedCount(
		t,
		"mutexorder",
		"mutex",
		1,
	)
}

// TestRegression_MutexBetween reports a mutex with data above it and data below it.
// The rule puts the mutex immediately above the data it guards.
//
// Revisions:
//   - 2026-10-21 16:10: initial creation
//   - 2026-10-21 16:41: drop the claim that guard reads only a last field
func TestRegression_MutexBetween(t *testing.T) {
	_NeedCount(
		t,
		"mutexbetween",
		"mutex",
		1,
	)
}

// TestRegression_RevisionIndent reports a revision bullet whose dash is not indented.
// The legal line has three spaces before the dash.
// gofmt rewrites two spaces into that form, so the fixture has no two-space bullet.
//
// Revisions:
//   - 2026-10-21 16:21: initial creation
//   - 2026-10-21 16:41: drop _Short; gofmt rewrites that bullet into the legal form
func TestRegression_RevisionIndent(t *testing.T) {
	_RunFixture(
		t,
		REVISION,
		"revisionindent",
	)
}

// TestRegression_MutexExample keeps the Store example free of a blank line.
// A blank line between fields is a fields error.
//
// Revisions:
//   - 2026-10-21 16:21: initial creation
//   - 2026-10-21 16:41: the example no longer uses a blank line
func TestRegression_MutexExample(t *testing.T) {
	text := _KitText(
		t,
	)
	if strings.Contains(
		text,
		"The blank line says that",
	) {
		t.Fatal(
			"go.md still says the blank line shows an unguarded field",
		)
	}

	start := strings.Index(
		text,
		"type Store struct {",
	)
	if start < 0 {
		t.Fatal(
			"go.md has no Store example",
		)
	}

	end := strings.Index(
		text[start:],
		"}",
	)
	if end < 0 {
		t.Fatal(
			"Store example has no close",
		)
	}

	body := text[start : start+end]
	if strings.Contains(
		body,
		"\n\n",
	) {
		t.Fatal(
			"Store example still has a blank line",
		)
	}
}

// TestRegression_CheckerTable reports a checker with no row in the go.md table.
// body and guard run, and the table does not name them.
//
// Revisions:
//   - 2026-10-21 16:21: initial creation
func TestRegression_CheckerTable(t *testing.T) {
	text := _KitText(
		t,
	)

	for _, phrase := range []string{
		"A function body uses more than one line",
		"A deferred closure uses more than one line",
		"A mutex sits immediately above the data it guards",
		"A revision bullet starts with two spaces",
	} {
		if strings.Contains(
			text,
			phrase,
		) {
			continue
		}

		t.Fatalf(
			"go.md table has no %q",
			phrase,
		)
	}
}

// _Run sets the module flag and runs one analyser on one fixture package.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-21 13:09: rename so the command can share this package
func _RunFixture(
	t *testing.T,
	checker *analysis.Analyzer,
	pkg string,
) {
	t.Helper()

	err := checker.Flags.Set(
		"module",
		pkg,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	analysistest.Run(
		t,
		analysistest.TestData(),
		checker,
		pkg,
	)
}

// TestLine locks the line an agent reads.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func TestLine(t *testing.T) {
	cases := []struct {
		name    string
		level   string
		rule    string
		message string
		fix     string
		want    string
	}{
		{
			name:    "error",
			level:   LEVEL_ERROR,
			rule:    "lead",
			message: "unexported name must start with _ and a capital letter",
			fix:     "edit the name",
			want: "error: lead: " +
				"unexported name must start with _ and a capital letter. " +
				"fix: edit the name",
		},
		{
			name:    "warning",
			level:   LEVEL_WARNING,
			rule:    "lead",
			message: "unexported name must start with _ and a capital letter",
			fix:     "edit the name",
			want: "warning: lead: " +
				"unexported name must start with _ and a capital letter. " +
				"fix: edit the name",
		},
		{
			name:    "log",
			level:   LEVEL_LOG,
			rule:    "convention",
			message: "1 packages, 0 errors, 0 warnings",
			want:    "log: convention: 1 packages, 0 errors, 0 warnings",
		},
	}

	for _, tc := range cases {
		t.Run(
			tc.name,
			func(t *testing.T) {
				got := Line(
					tc.level,
					tc.rule,
					tc.message,
					tc.fix,
				)
				if got != tc.want {
					t.Fatalf(
						"line = %s",
						got,
					)
				}

				errors, warnings := Count(
					got,
				)

				switch tc.level {
				case LEVEL_ERROR:
					_Count(
						t,
						[2]int{errors, warnings},
						[2]int{1, 0},
					)
				case LEVEL_WARNING:
					_Count(
						t,
						[2]int{errors, warnings},
						[2]int{0, 1},
					)
				default:
					_Count(
						t,
						[2]int{errors, warnings},
						[2]int{0, 0},
					)
				}
			},
		)
	}
}

// TestSelect locks the checker list a flag selects.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func TestSelect(t *testing.T) {
	got, err := Select(
		"",
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	if Names(
		got,
	) != Names(
		CHECKS,
	) {
		t.Fatal(
			Names(
				got,
			),
		)
	}

	got, err = Select(
		"call,literal,call",
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	if Names(
		got,
	) != "literal call" {
		t.Fatal(
			Names(
				got,
			),
		)
	}

	_, err = Select(
		"nope",
	)
	if err == nil {
		t.Fatal(
			"missing error",
		)
	}
}

// TestRun reads the log from a clean run of the command.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func TestRun(t *testing.T) {
	var (
		text = _Command(
			t,
			".",
		)
		start = "log: convention: check " + Names(
			CHECKS,
		)
	)
	if !strings.Contains(
		text,
		start,
	) {
		t.Fatalf(
			"log = %s",
			text,
		)
	}

	if !strings.Contains(
		text,
		"0 errors, 0 warnings",
	) {
		t.Fatalf(
			"log = %s",
			text,
		)
	}
}

// TestCheckFlag runs one named checker.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func TestCheckFlag(t *testing.T) {
	text := _Command(
		t,
		"-check=banner",
		".",
	)
	if !strings.Contains(
		text,
		"log: convention: check banner",
	) {
		t.Fatalf(
			"log = %s",
			text,
		)
	}

	if strings.Contains(
		text,
		"check revision",
	) {
		t.Fatalf(
			"log = %s",
			text,
		)
	}
}

// TestCheckUnknown reports a name that is not a checker.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func TestCheckUnknown(t *testing.T) {
	var (
		cmd = exec.Command(
			"go",
			"run",
			".",
			"-check=nope",
			".",
		)
		out, err = cmd.CombinedOutput()
	)
	if err == nil {
		t.Fatal(
			out,
		)
	}

	text := string(out)
	if !strings.Contains(
		text,
		"unknown check nope",
	) {
		t.Fatalf(
			"log = %s",
			text,
		)
	}

	if !strings.Contains(
		text,
		"fix: use "+Names(
			CHECKS,
		),
	) {
		t.Fatalf(
			"log = %s",
			text,
		)
	}
}

// _Command runs the convention command and returns its output.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _Command(
	t *testing.T,
	args ...string,
) string {
	t.Helper()

	var (
		cmd = exec.Command(
			"go",
			append(
				[]string{"run", "."},
				args...,
			)...,
		)
		out, err = cmd.CombinedOutput()
	)
	if err != nil {
		t.Fatalf(
			"run: %v\n%s",
			err,
			out,
		)
	}

	return string(out)
}

// _Count fails the test when the tallies differ from the expected pair.
//
// Revisions:
//   - 2026-10-04 01:38: initial creation
func _Count(
	t *testing.T,
	got [2]int,
	want [2]int,
) {
	t.Helper()

	if got == want {
		return
	}

	t.Fatalf(
		"count = %d errors, %d warnings",
		got[0],
		got[1],
	)
}

// _NeedCount fails when needle appears a different number of times.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
func _NeedCount(
	t *testing.T,
	pkg string,
	needle string,
	want int,
) {
	t.Helper()

	var (
		text = _FixtureText(
			t,
			pkg,
		)
		got = strings.Count(
			text,
			needle,
		)
	)
	if got == want {
		return
	}

	t.Fatalf(
		"reports of %q = %d, want %d\n%s",
		needle,
		got,
		want,
		text,
	)
}

// _FixtureText runs every checker on one testdata package and returns the findings.
//
// Revisions:
//   - 2026-10-21 13:25: initial creation
func _FixtureText(
	t *testing.T,
	pkg string,
) string {
	t.Helper()

	err := POINTER.Flags.Set(
		"module",
		pkg,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	var (
		dir = filepath.Join(
			analysistest.TestData(),
			"src",
			pkg,
		)
		loaded []*packages.Package
	)

	loaded, err = packages.Load(
		&packages.Config{
			Mode: packages.LoadSyntax | packages.NeedModule,
			Dir:  dir,
		},
		".",
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	if len(
		loaded,
	) == 0 {
		t.Fatal(
			"no packages",
		)
	}

	for _, item := range loaded {
		if len(
			item.Errors,
		) > 0 {
			t.Fatal(
				item.Errors[0],
			)
		}
	}

	graph, err := checker.Analyze(
		CHECKS,
		loaded,
		nil,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	var text strings.Builder

	for _, act := range graph.Roots {
		if act.Err != nil {
			text.WriteString(
				act.Err.Error(),
			)
			text.WriteString(
				"\n",
			)
		}

		for _, diag := range act.Diagnostics {
			text.WriteString(
				diag.Message,
			)
			text.WriteString(
				"\n",
			)
		}
	}

	return text.String()
}

// _KitText reads .guidelines/conventions/go.md from the module root.
//
// Revisions:
//   - 2026-10-21 16:21: initial creation
func _KitText(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(
		0,
	)
	if !ok {
		t.Fatal(
			"no caller",
		)
	}

	var (
		path = filepath.Join(
			filepath.Dir(
				file,
			),
			"..",
			"..",
			"..",
			".guidelines",
			"conventions",
			"go.md",
		)
		text, err = os.ReadFile(
			path,
		)
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	return string(
		text,
	)
}

// TestChanged_RejectsPaths fails when -changed has package paths.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func TestChanged_RejectsPaths(t *testing.T) {
	opt := _Flags(
		[]string{
			"-changed",
			"./...",
		},
	)
	if opt.code == 0 {
		t.Fatal(
			"want a failure",
		)
	}
}

// TestRegression_ChangedFile keeps a finding in a changed file and drops one in an old file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func TestRegression_ChangedFile(t *testing.T) {
	var (
		dir = _ChangedRepo(
			t,
		)
		clean = _ChangedRun(
			t,
			dir,
		)
	)
	if strings.Contains(
		clean,
		"b.go",
	) {
		t.Fatalf(
			"old file reported:\n%s",
			clean,
		)
	}

	if strings.Contains(
		clean,
		"error:",
	) {
		t.Fatalf(
			"clean diff reported:\n%s",
			clean,
		)
	}

	err := os.WriteFile(
		filepath.Join(
			dir,
			"b.go",
		),
		[]byte("package p\n\nfunc Bad() { return } // mark\n"),
		0o644,
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}

	text := _ChangedRun(
		t,
		dir,
	)
	if !strings.Contains(
		text,
		"b.go",
	) {
		t.Fatalf(
			"changed file missing:\n%s",
			text,
		)
	}

	if strings.Contains(
		text,
		"a.go",
	) {
		t.Fatalf(
			"old file reported:\n%s",
			text,
		)
	}
}

// _ChangedRepo builds a module whose bad file is already committed.
// The good file is then edited, so only that file is in the diff.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _ChangedRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	_Put(
		t,
		filepath.Join(
			dir,
			"go.mod",
		),
		"module example.com/changed\n\ngo 1.26\n",
	)
	_Put(
		t,
		filepath.Join(
			dir,
			"a.go",
		),
		"package p\n\nfunc Good() {\n\treturn\n}\n",
	)
	_Put(
		t,
		filepath.Join(
			dir,
			"b.go",
		),
		"package p\n\nfunc Bad() { return }\n",
	)
	_GitDir(
		t,
		dir,
		"init",
	)
	_GitDir(
		t,
		dir,
		"add",
		"--",
		"go.mod",
		"a.go",
		"b.go",
	)
	_GitDir(
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
	_Put(
		t,
		filepath.Join(
			dir,
			"a.go",
		),
		"package p\n\n// Good stays on more than one line.\nfunc Good() {\n\treturn\n}\n",
	)

	return dir
}

// _ChangedRun executes convention -changed in dir.
// A non-zero status is part of the result when the changed file has a finding.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _ChangedRun(
	t *testing.T,
	dir string,
) string {
	t.Helper()

	cmd := exec.Command(
		"go",
		"run",
		".",
		"-changed",
		"-dir",
		dir,
		"-check=body",
	)

	var (
		out, err = cmd.CombinedOutput()
		text     = string(
			out,
		)
	)
	if err != nil && !strings.Contains(
		text,
		"error:",
	) {
		t.Fatalf(
			"run: %v\n%s",
			err,
			text,
		)
	}

	return text
}

// _Put writes one file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Put(
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

// _GitDir runs git in dir and fails the test on a non-zero status.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _GitDir(
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
