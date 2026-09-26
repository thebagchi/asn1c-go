package compiler_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Where the specification and the grammar are, from this package's directory.
const (
	EBNF_PATH     = "../specs/asn1.ebnf"
	GRAMMAR_PATH  = "grammar.y"
	COVERAGE_PATH = "testdata/coverage.tsv"
)

// How a production may be reached when no rule carries its name. Only SAME
// names a rule, which is why only it is looked up.
const (
	REACHED_SAME     = "same"
	REACHED_LEXER    = "lexer"
	REACHED_RESOLVER = "resolver"
	REACHED_DIRECTED = "directed"
	REACHED_OUTSIDE  = "outside"
)

// A production of the EBNF, and a rule of the grammar. The EBNF writes "::="
// after the name and hyphenates; grammar.y cannot, so a name there is one
// word followed by a colon at the start of a line.
var (
	RE_PRODUCTION = regexp.MustCompile(`(?m)^([A-Za-z][A-Za-z0-9-]*)\s*::=`)
	RE_RULE       = regexp.MustCompile(`(?m)^([A-Za-z][A-Za-z0-9]*):$`)
)

// The separator of testdata/coverage.tsv, and the character that opens a
// comment in it.
const (
	COVERAGE_SEPARATOR = "\t"
	COVERAGE_COMMENT   = "#"
	COVERAGE_COLUMNS   = 3
)

// TestGrammarCoverage checks that every production of the specification is
// accounted for: either grammar.y has a rule of that name, or the coverage
// table says which rule carries it, which pass reads it, or why no rule can.
//
// A name-by-name diff would report two thirds of ASN.1 missing and be worth
// nothing, because most of what it found is a collapse the grammar makes on
// purpose - X.680 gives BooleanType and sixteen more a production each and
// they differ only in a word. So the table carries the answer and this
// checks the table, in both directions: a production in neither place fails,
// and so does a row for a production that has since got a rule of its own.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func TestGrammarCoverage(t *testing.T) {
	productions := _Productions(t)
	rules := _Rules(t)
	coverage := _Coverage(t)

	counts := map[string]int{}

	for _, production := range productions {
		reached, ok := coverage[production]

		switch {
		case rules[production] && ok:
			t.Errorf(
				"%s: grammar.y has a rule of this name, so its %s row in %s"+
					" is stale - delete it",
				production, reached.how, COVERAGE_PATH,
			)

		case rules[production]:
			counts["a rule of its own name"]++

		case !ok:
			t.Errorf(
				"%s: no rule of this name in grammar.y and no row in %s."+
					" Write the rule, or say there how it is reached",
				production, COVERAGE_PATH,
			)

		default:
			counts[reached.how]++
		}
	}

	_CheckRows(t, productions, rules, coverage)
	_Report(t, len(productions), counts)
}

// _Reached is one row of the coverage table: how a production is reached,
// and what reaches it.
type _Reached struct {
	how  string
	what string
}

// _CheckRows checks the table's own side of the bargain: a row must name a
// production the specification has, and a row that names a carrying rule must
// name one the grammar still has.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func _CheckRows(
	t *testing.T,
	productions []string,
	rules map[string]bool,
	coverage map[string]*_Reached,
) {
	t.Helper()

	known := map[string]bool{}
	for _, production := range productions {
		known[production] = true
	}

	for _, production := range _Sorted(coverage) {
		reached := coverage[production]

		if !known[production] {
			t.Errorf(
				"%s: %s has a row for this, and %s no production - delete it",
				production, COVERAGE_PATH, EBNF_PATH,
			)
		}

		if reached.how != REACHED_SAME {
			continue
		}

		if !rules[reached.what] {
			t.Errorf(
				"%s: its row says %s carries it, and grammar.y has no such"+
					" rule any more",
				production, reached.what,
			)
		}
	}
}

// _Report logs what the grammar covers and how, which is the number worth
// reading when this passes.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func _Report(t *testing.T, total int, counts map[string]int) {
	t.Helper()

	t.Logf("%s productions: %d", EBNF_PATH, total)

	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		t.Logf("  %-24s %3d", key, counts[key])
	}
}

// _Productions returns every production the specification defines, in the
// order it defines them, each once.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func _Productions(t *testing.T) []string {
	t.Helper()

	data, err := os.ReadFile(EBNF_PATH)
	if err != nil {
		t.Fatalf("failed to read %s: %v", EBNF_PATH, err)
	}

	seen := map[string]bool{}

	var productions []string

	for _, match := range RE_PRODUCTION.FindAllStringSubmatch(string(data), -1) {
		name := match[1]
		if seen[name] {
			continue
		}

		seen[name] = true
		productions = append(productions, name)
	}

	if len(productions) == 0 {
		t.Fatalf("no productions found in %s", EBNF_PATH)
	}

	return productions
}

// _Rules returns the name of every rule grammar.y declares.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func _Rules(t *testing.T) map[string]bool {
	t.Helper()

	data, err := os.ReadFile(GRAMMAR_PATH)
	if err != nil {
		t.Fatalf("failed to read %s: %v", GRAMMAR_PATH, err)
	}

	rules := map[string]bool{}
	for _, match := range RE_RULE.FindAllStringSubmatch(string(data), -1) {
		rules[match[1]] = true
	}

	if len(rules) == 0 {
		t.Fatalf("no rules found in %s", GRAMMAR_PATH)
	}

	return rules
}

// _Coverage reads the table of productions no rule names.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func _Coverage(t *testing.T) map[string]*_Reached {
	t.Helper()

	data, err := os.ReadFile(COVERAGE_PATH)
	if err != nil {
		t.Fatalf("failed to read %s: %v", COVERAGE_PATH, err)
	}

	ways := map[string]bool{
		REACHED_SAME:     true,
		REACHED_LEXER:    true,
		REACHED_RESOLVER: true,
		REACHED_DIRECTED: true,
		REACHED_OUTSIDE:  true,
	}

	coverage := map[string]*_Reached{}

	for index, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, COVERAGE_COMMENT) {
			continue
		}

		columns := strings.Split(line, COVERAGE_SEPARATOR)
		if len(columns) != COVERAGE_COLUMNS {
			t.Fatalf(
				"%s line %d: %d tab-separated columns, want %d",
				COVERAGE_PATH, index+1, len(columns), COVERAGE_COLUMNS,
			)
		}

		if !ways[columns[1]] {
			t.Fatalf(
				"%s line %d: %q is not a way a production is reached",
				COVERAGE_PATH, index+1, columns[1],
			)
		}

		if previous, ok := coverage[columns[0]]; ok {
			t.Fatalf(
				"%s line %d: %s already has a row, saying %s",
				COVERAGE_PATH, index+1, columns[0], previous.how,
			)
		}

		coverage[columns[0]] = &_Reached{how: columns[1], what: columns[2]}
	}

	return coverage
}

// _Sorted returns the table's productions in a fixed order, so that what
// this test reports does not depend on how a map was walked.
//
// Revisions:
//   - 2026-09-25 10:38: initial creation
func _Sorted(coverage map[string]*_Reached) []string {
	names := make([]string, 0, len(coverage))
	for name := range coverage {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}
