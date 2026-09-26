package compiler

import (
	"fmt"
	"os"
)

// TRACE_ENV is the environment variable that turns the grammar's rule
// trace on. Any value other than the empty string does it, so
// "ASN1_TRACE=1 go test ./compiler/" is enough to see a parse go by.
const (
	TRACE_ENV = "ASN1_TRACE"
)

// TRACE reports whether the trace is on, read once here rather than at
// every reduction: a grammar of this size reduces often enough that the
// lookup would show up in a parse, and nothing changes the variable while
// one runs. A test that wants the trace sets it directly.
var (
	TRACE = os.Getenv(TRACE_ENV) != ""
)

// Trace reports that rule reduced and what it built, in the order the
// parser reduced them, which is bottom-up and so reads inside-out: the
// innermost rule of a construct is the first line about it. The rule
// names one of grammar.y's alternatives - "Exports: #2" is the second
// alternative written under Exports - so a line leads back to the text
// that produced it. It writes to standard error so that a parse being
// traced and a parse being piped somewhere do not mix.
//
// This is the trace to reach for when a rule matches something it should
// not, or builds the wrong value. For the complementary question - why
// the parser chose one rule over another, or where a state came from -
// set the generated asn1Debug to 4 and read it beside y.output, which
// names the states by number.
//
// Revisions:
//   - 2026-09-24 10:24: initial creation
func Trace(rule string, value any) {
	if !TRACE {
		return
	}

	fmt.Fprintf(os.Stderr, "asn1: %-34s %v\n", rule, value)
}
