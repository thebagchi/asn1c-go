// This test is external, unlike the two beside it: it reaches the parser
// only through ParseModules, so it has no reason to be inside the package.
package compiler_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/compiler"
)

// Where the corpora live. The specifications sit outside this package
// because they are not this package's fixtures: they are whole protocols
// that any part of the compiler will want to read, and tools/corpus writes
// them. See testdata/PROVENANCE beside each for where they came from.
const (
	SPECS_DIR  = "../testdata/3gpp"
	ERLANG_DIR = "testdata/otp"
	OWN_DIR    = "testdata/asn1c"

	// The suffix each of this project's own modules carries, which says
	// what the parser must do with it. Every file under OWN_DIR has one
	// or the other, and TestOwnCorpus fails a file that has neither -
	// a module whose verdict is not written down is a module nobody can
	// tell has stopped doing what it was written for.
	MUST_PARSE = "-ok.asn1"
	MUST_NOT   = "-nok.asn1"

	// How many of the Erlang corpus's 360 modules parse. lib/review.md 11.21
	// says what the rest need.
	ERLANG_MODULES = 344
)

// TestSpecifications parses the 3GPP specifications under testdata/3gpp,
// which are the largest ASN.1 anyone writes and were not written with any
// parser in mind. They are the other half of the corpus: asn1c's files are
// small and aimed at one construct each, and these are whole protocols.
//
// Every one of them must parse. There is no expectation to raise here,
// because a specification that stops parsing is a regression and not a
// gap - tools/corpus/extract.py says where each comes from.
//
// Revisions:
//   - 2026-09-24 20:14: initial creation
func TestSpecifications(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(SPECS_DIR, "*.asn1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("no specifications under %s", SPECS_DIR)
	}

	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		name := filepath.Base(path)

		modules, err := compiler.ParseModules(source)
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		if len(modules) == 0 {
			t.Errorf("%s: parsed, but found no modules", name)
		}
	}
}

// TestErlangCorpus parses the modules Erlang/OTP tests its own ASN.1
// compiler with. They are the third corpus and the most varied: X.500's
// directory services, the intelligent network protocols, and a long tail
// of modules written to exercise one corner each.
//
// Some of them are meant to be rejected - OTP tests its compiler's errors
// with them too - and their names do not say which, unlike asn1c's. So the
// count is asserted and the list is not, and a change that moves it has to
// say which way it moved.
//
// Revisions:
//   - 2026-09-24 20:41: initial creation
func TestErlangCorpus(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(ERLANG_DIR, "*.asn*"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("no modules under %s", ERLANG_DIR)
	}

	parsed := 0

	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		if _, err := compiler.ParseModules(source); err == nil {
			parsed++
		}
	}

	// 344 of the 360 parse. What the rest need is in lib/review.md, and
	// an unknown number of them are meant not to parse at all. The count is
	// exact rather than a floor so that a change that trades one module for
	// another cannot pass unnoticed.
	if parsed != ERLANG_MODULES {
		t.Errorf("parsed %d modules, want %d", parsed, ERLANG_MODULES)
	}
}

// TestOwnCorpus parses this project's own modules, which say what the
// parser must do with them in their names: "-ok.asn1" must parse and
// "-nok.asn1" must not.
//
// The modules ending -nok are the ones this grammar refuses by decision,
// and each says in its first lines which decision and why, with the
// section of lib/review.md that records it. If one of them starts
// parsing, a decision was reversed without anybody meaning to - which is
// the test the two borrowed corpora cannot give, since they say what some
// other compiler accepts and not what this one decided.
//
// Unlike those two this asserts a verdict per file rather than a count,
// because every one of these is ours and every one must hold. A file with
// neither suffix fails as well: the convention is the test.
//
// Revisions:
//   - 2026-09-24 21:03: initial creation
//   - 2026-09-24 23:05: the verdict is a suffix on the name
func TestOwnCorpus(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(OWN_DIR, "*.asn1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("no modules under %s", OWN_DIR)
	}

	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		name := filepath.Base(path)
		_, err = compiler.ParseModules(source)

		switch {
		case strings.HasSuffix(name, MUST_NOT):
			if err == nil {
				t.Errorf("%s: parsed, and it is written not to", name)
			}

		case strings.HasSuffix(name, MUST_PARSE):
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}

		default:
			t.Errorf("%s: name says neither %q nor %q", name,
				MUST_PARSE, MUST_NOT)
		}
	}
}
