// Package vectorize decides whether a Go loop may be rewritten as a vector kernel.
//
// It answers one question - may this loop be vectorised - and deliberately not the other
// one, which is how. Codegen without this analysis is unsafe in a way that does not
// announce itself: a loop with a carried dependency still compiles, still runs, and
// silently produces different numbers. So the analysis is the part that has to be right
// first, and it is useful on its own, because "this loop cannot be vectorised, and here is
// the statement that stops it" is what a person needs before hand-writing a kernel.
//
// The class it recognises is narrow on purpose: an element-wise map over a slice with a
// constant stencil.
//
//	for idx := 1; idx < len(src); idx++ {
//	    dst[idx] = src[idx-1]<<free | src[idx]>>used
//	}
//
// Unit stride, one store per iteration, every load at a fixed offset from the induction
// variable, and every other operand loop-invariant. That is the shape this repository's
// hot loops already have, and it is the shape a lane-parallel kernel maps onto without any
// reordering.
//
// Everything else is refused with a reason. The refusal is the feature: a vectoriser that
// guesses is worse than none, because the wrong answer looks exactly like the right one.
package vectorize

import (
	"fmt"
	"go/ast"
	"go/token"
)

// Verdict is what the analysis concluded about one loop.
type Verdict struct {
	position token.Position
	safe     bool
	reason   string
	stencil  []int
	store    string
	loads    []string
}

// Position is where the loop begins.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) Position() token.Position {
	return v.position
}

// Safe reports whether the loop may be rewritten as a vector kernel.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) Safe() bool {
	return v.safe
}

// Reason names what stopped the loop, or describes the shape that was recognised.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) Reason() string {
	return v.reason
}

// Stencil is the set of offsets from the induction variable that the body reads.
//
// It is what decides how much a kernel must overlap its blocks: a stencil of {-1, 0} means
// every block needs one element of the block before it, which is exactly the overlap the
// existing shift kernel loads. An empty stencil means the body reads no indexed element.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) Stencil() []int {
	return v.stencil
}

// Store is the slice the loop writes.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) Store() string {
	return v.store
}

// Loads are the slices the loop reads, in the order first seen.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) Loads() []string {
	return v.loads
}

// String renders a verdict for a report.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func (v *Verdict) String() string {
	if !v.safe {
		return fmt.Sprintf("%s: no - %s", v.position, v.reason)
	}

	return fmt.Sprintf(
		"%s: yes - %s writes %s, stencil %v",
		v.position, v.reason, v.store, v.stencil,
	)
}

// Analyze classifies every loop in a file.
//
// A range loop is refused rather than skipped. Skipping it would be the more natural
// implementation - it is a different node type and none of the analysis below applies - but
// a loop left out of the report is indistinguishable from one that was examined and found
// fine, and a report whose denominator is wrong is worse than no report.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
//   - 2026-09-23 01:41: range loops are refused with a reason instead of being skipped,
//     which had left them out of the report entirely
//   - 2026-09-23 01:58: range-over-index is analysed rather than refused. It is the form
//     most of this repository's indexed loops use, and it is the easier of the two: the
//     stride and the bound are the language's rather than something to read off a clause
func Analyze(set *token.FileSet, file *ast.File) []*Verdict {
	var (
		found []*Verdict
	)

	ast.Inspect(file, func(node ast.Node) bool {
		switch loop := node.(type) {
		case *ast.ForStmt:
			found = append(found, _Classify(set, loop))
		case *ast.RangeStmt:
			found = append(found, _ClassifyRange(set, loop))
		}

		return true
	})

	return found
}
