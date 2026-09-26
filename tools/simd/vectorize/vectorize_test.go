package vectorize_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/tools/simd/vectorize"
)

// Each case is one loop body wrapped in a function, with what the analysis must conclude.
//
// The refusals matter more than the acceptances. An analysis that accepts too little costs
// speed that was already being lost; one that accepts too much rewrites a loop into
// something that computes different numbers and says nothing. So every shape that must be
// refused has a case here, and the reason is matched too - a loop refused for the wrong
// reason is a check that will stop working the moment the shape changes.
var (
	CASES = []struct {
		name    string
		body    string
		safe    bool
		reason  string
		stencil []int
	}{
		{
			name: "funnel shift, the kernel this repository already has",
			body: "for idx := 1; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx-1]<<free | src[idx]>>used }",
			safe:    true,
			reason:  "element-wise",
			stencil: []int{-1, 0},
		},
		{
			name: "pure element-wise",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx] ^ mask }",
			safe:    true,
			reason:  "element-wise",
			stencil: []int{0},
		},
		{
			name: "in place at the same offset is safe",
			body: "for idx := 0; idx < len(buf); idx++ " +
				"{ buf[idx] = buf[idx] & mask }",
			safe:    true,
			reason:  "element-wise",
			stencil: []int{0},
		},
		{
			name: "reads what it has already written",
			body: "for idx := 1; idx < len(buf); idx++ " +
				"{ buf[idx] = buf[idx-1] + src[idx] }",
			safe:   false,
			reason: "already overwritten",
		},
		{
			name:   "accumulator carries state between iterations",
			body:   "for idx := 0; idx < len(src); idx++ { total = total + src[idx] }",
			safe:   false,
			reason: "does not store into a slice element",
		},
		{
			name: "two statements",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx]; total++ }",
			safe:   false,
			reason: "want one store",
		},
		{
			name: "early exit",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ if src[idx] == 0 { break } }",
			safe:   false,
			reason: "not an assignment",
		},
		{
			name: "calls a function",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ dst[idx] = lookup(src[idx]) }",
			safe:   false,
			reason: "calls a function",
		},
		{
			name: "division has no lane-wise form on this target",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx] / step }",
			safe:   false,
			reason: "no lane-wise form",
		},
		{
			name:   "updates in place",
			body:   "for idx := 0; idx < len(src); idx++ { dst[idx] += src[idx] }",
			safe:   false,
			reason: "carries state between iterations",
		},
		{
			name:   "stride above one",
			body:   "for idx := 0; idx < len(src); idx += 2 { dst[idx] = src[idx] }",
			safe:   false,
			reason: "needs a gather",
		},
		{
			name:    "range over index is the easy case, not a refusal",
			body:    "for idx := range src { dst[idx] = src[idx] ^ mask }",
			safe:    true,
			reason:  "element-wise",
			stencil: []int{0},
		},
		{
			name:   "range over values copies the element",
			body:   "for _, item := range src { dst[0] = item }",
			safe:   false,
			reason: "ranges over values",
		},
		{
			name:   "range discarding the index",
			body:   "for _ = range src { dst[0] = 1 }",
			safe:   false,
			reason: "discards its index",
		},
		{
			name:   "index is not affine in the loop variable",
			body:   "for idx := 0; idx < len(src); idx++ { dst[idx] = src[idx*2] }",
			safe:   false,
			reason: "not the loop variable plus a constant",
		},
		{
			name:   "counts downward",
			body:   "for idx := len(src); idx > 0; idx++ { dst[idx] = src[idx] }",
			safe:   false,
			reason: "does not count upward",
		},
		{
			name: "conversion is allowed, it is a width change not a call",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ dst[idx] = uint64(src[idx]) << shift }",
			safe:   true,
			reason: "element-wise",
		},
	}
)

// TestClassifyMatchesExpectation runs every shape past the analysis.
func TestClassifyMatchesExpectation(t *testing.T) {
	t.Parallel()

	for _, item := range CASES {
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			verdicts := _Analyze(t, item.body)
			if len(verdicts) != 1 {
				t.Fatalf("want one loop, found %d", len(verdicts))
			}

			found := verdicts[0]

			if found.Safe() != item.safe {
				t.Fatalf(
					"want safe=%v, got safe=%v (%s)",
					item.safe, found.Safe(), found.Reason(),
				)
			}

			if !strings.Contains(found.Reason(), item.reason) {
				t.Errorf(
					"reason %q does not mention %q",
					found.Reason(), item.reason,
				)
			}

			if item.stencil != nil {
				_Equal(t, found.Stencil(), item.stencil)
			}
		})
	}
}

// TestStencilDrivesBlockOverlap checks the number a kernel actually needs from the analysis.
//
// The stencil is not decoration. A kernel that vectorises a loop reading src[idx-1] must
// load one element before each block, and the existing hand-written shift kernel does
// exactly that. If the analysis reported the wrong span, generated code would read the
// wrong address at every block boundary - which is where the hand-written kernel's own bugs
// were, so it is the number most worth checking.
func TestStencilDrivesBlockOverlap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    string
		overlap int
	}{
		{
			name:    "no overlap",
			body:    "for idx := 0; idx < len(src); idx++ { dst[idx] = src[idx] }",
			overlap: 0,
		},
		{
			name: "one behind",
			body: "for idx := 1; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx-1] | src[idx] }",
			overlap: 1,
		},
		{
			name: "one ahead",
			body: "for idx := 0; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx] | src[idx+1] }",
			overlap: 1,
		},
		{
			name: "three wide",
			body: "for idx := 1; idx < len(src); idx++ " +
				"{ dst[idx] = src[idx-1] | src[idx] | src[idx+1] }",
			overlap: 2,
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			found := _Analyze(t, item.body)[0]
			if !found.Safe() {
				t.Fatalf("refused: %s", found.Reason())
			}

			var (
				stencil = found.Stencil()
				span    = stencil[len(stencil)-1] - stencil[0]
			)

			if span != item.overlap {
				t.Errorf(
					"stencil %v spans %d, want %d",
					stencil, span, item.overlap,
				)
			}
		})
	}
}

// _Analyze parses one loop body and classifies it.
func _Analyze(t *testing.T, body string) []*vectorize.Verdict {
	t.Helper()

	const TEMPLATE = "package probe\n\nfunc probe() {\n\t%s\n}\n"

	var (
		set  = token.NewFileSet()
		text = strings.Replace(TEMPLATE, "%s", body, 1)
	)

	file, err := parser.ParseFile(set, "probe.go", text, 0)
	if err != nil {
		t.Fatalf("parse %q: %v", body, err)
	}

	return vectorize.Analyze(set, file)
}

// _Equal compares two offset sets.
func _Equal(t *testing.T, got, want []int) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("stencil %v, want %v", got, want)
	}

	for idx := range got {
		if got[idx] != want[idx] {
			t.Fatalf("stencil %v, want %v", got, want)
		}
	}
}
