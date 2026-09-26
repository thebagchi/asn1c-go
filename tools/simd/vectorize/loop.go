package vectorize

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
)

// LANE_OPERATORS are the operators a lane may compute. Each acts on one element and needs
// nothing from any other lane, which is the whole of why the loop can be split.
//
// Division and modulo are absent deliberately: AVX2 has no integer divide, so a loop
// containing one is not vectorisable on this target however well-behaved it otherwise is.
// Comparisons are absent because a lane-wise comparison yields a mask rather than a value,
// which is a different kind of kernel than this recognises.
var (
	LANE_OPERATORS = map[token.Token]bool{
		token.ADD: true,
		token.SUB: true,
		token.MUL: true,
		token.AND: true,
		token.OR:  true,
		token.XOR: true,
		token.SHL: true,
		token.SHR: true,
	}
)

// _Classify decides whether one loop may be rewritten as a vector kernel.
//
// Every check below refuses rather than assumes. A loop this cannot prove safe is reported
// unsafe even when it happens to be fine, because the cost of the two mistakes is not
// symmetric: a missed vectorisation costs speed that was already being lost, and a wrong
// one silently changes results.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Classify(set *token.FileSet, loop *ast.ForStmt) *Verdict {
	var (
		at = set.Position(loop.Pos())
	)

	name, reason := _Induction(loop)
	if name == "" {
		return _Refuse(at, reason)
	}

	return _Shape(at, loop.Body, name)
}

// _Shape examines a loop body once the induction variable and unit stride are established.
//
// Revisions:
//   - 2026-09-23 01:58: initial creation
func _Shape(at token.Position, block *ast.BlockStmt, name string) *Verdict {
	body, reason := _SingleAssignment(block)
	if body == nil {
		return _Refuse(at, reason)
	}

	store, offset, reason := _StoreTarget(body, name)
	if store == "" {
		return _Refuse(at, reason)
	}

	loads, stencil, reason := _LoadSet(body.Rhs[0], name)
	if reason != "" {
		return _Refuse(at, reason)
	}

	if reason := _Dependence(store, offset, loads, stencil); reason != "" {
		return _Refuse(at, reason)
	}

	return &Verdict{
		position: at,
		safe:     true,
		reason:   "element-wise map, unit stride",
		stencil:  stencil,
		store:    store,
		loads:    loads,
	}
}

// _ClassifyRange decides whether a range loop may be rewritten as a vector kernel.
//
// "for idx := range src" is the easier of the two loop shapes, not the harder one: the
// stride is one and the bound is len(src) because the language says so, rather than because
// a clause was read and believed. Only the body has to be examined, and that is the same
// examination the three-clause form gets.
//
// The two-variable form is refused. "for idx, item := range src" copies the element into
// item, so the body reads a variable rather than an indexed slice, and the dependence
// question is about that copy instead. It is analysable, but it is a different analysis and
// pretending otherwise is how a vectoriser starts being wrong.
//
// Revisions:
//   - 2026-09-23 01:58: initial creation
func _ClassifyRange(set *token.FileSet, loop *ast.RangeStmt) *Verdict {
	var (
		at = set.Position(loop.Pos())
	)

	if loop.Value != nil {
		return _Refuse(
			at, "ranges over values rather than indices, so the element is copied",
		)
	}

	if loop.Key == nil {
		return _Refuse(at, "range loop binds no index")
	}

	name, ok := loop.Key.(*ast.Ident)
	if !ok || name.Name == "_" {
		return _Refuse(at, "range loop discards its index")
	}

	if loop.Tok != token.DEFINE {
		return _Refuse(at, "range loop assigns to an existing variable")
	}

	if _, ok := loop.X.(*ast.Ident); !ok {
		return _Refuse(at, "range expression is not a plain slice")
	}

	return _Shape(at, loop.Body, name.Name)
}

// _Refuse builds a negative verdict.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Refuse(at token.Position, reason string) *Verdict {
	return &Verdict{
		position: at,
		safe:     false,
		reason:   reason,
		stencil:  nil,
		store:    "",
		loads:    nil,
	}
}

// _Induction returns the loop's induction variable, or the reason there is not one.
//
// It wants the three-clause form with a unit increment. A range loop is not accepted even
// though it is often equivalent, because "for idx := range src" and "for idx, item := range
// src" differ in whether the element is copied, and the second is a different dependence
// question. Rejecting both is honest; accepting the first would invite the second.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Induction(loop *ast.ForStmt) (string, string) {
	if loop.Init == nil || loop.Cond == nil || loop.Post == nil {
		return "", "not a three-clause for loop"
	}

	name := _InitName(loop.Init)
	if name == "" {
		return "", "loop variable is not a single assignment"
	}

	if reason := _Bound(loop.Cond, name); reason != "" {
		return "", reason
	}

	if reason := _Step(loop.Post, name); reason != "" {
		return "", reason
	}

	return name, ""
}

// _InitName returns the variable the init clause establishes.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _InitName(init ast.Stmt) string {
	assign, ok := init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return ""
	}

	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return ""
	}

	return ident.Name
}

// _Bound checks that the loop runs while the induction variable is below something that
// does not change inside it.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Bound(cond ast.Expr, name string) string {
	compare, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return "loop condition is not a comparison"
	}

	if compare.Op != token.LSS && compare.Op != token.LEQ {
		return "loop does not count upward"
	}

	ident, ok := compare.X.(*ast.Ident)
	if !ok || ident.Name != name {
		return "loop condition does not test the loop variable"
	}

	return ""
}

// _Step checks that the loop advances by one.
//
// A stride above one is not refused because it is unsafe - it is not - but because a kernel
// for it gathers rather than loads, which is a different kernel and much slower. Saying so
// here keeps the reason accurate.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Step(post ast.Stmt, name string) string {
	switch step := post.(type) {
	case *ast.IncDecStmt:
		ident, ok := step.X.(*ast.Ident)
		if !ok || ident.Name != name || step.Tok != token.INC {
			return "loop does not advance by one"
		}

		return ""
	case *ast.AssignStmt:
		return "loop advances by a step other than one, which needs a gather"

	default:
		return "loop advance is not recognised"
	}
}

// _SingleAssignment returns the body's one assignment, or the reason the body is not one.
//
// Restricting the body to a single store is what makes everything after it sound. With no
// other statement there is nothing that can carry state between iterations, nothing that
// can exit early, and every identifier the body reads is necessarily unchanged by the loop
// - so loop-invariance needs no separate proof.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _SingleAssignment(body *ast.BlockStmt) (*ast.AssignStmt, string) {
	if body == nil || len(body.List) == 0 {
		return nil, "loop body is empty"
	}

	if len(body.List) > 1 {
		return nil, fmt.Sprintf(
			"loop body has %d statements, want one store", len(body.List),
		)
	}

	assign, ok := body.List[0].(*ast.AssignStmt)
	if !ok {
		return nil, "loop body is not an assignment"
	}

	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil, "loop body assigns more than one value"
	}

	if assign.Tok != token.ASSIGN {
		return nil, "loop body updates in place, which carries state between iterations"
	}

	return assign, ""
}

// _StoreTarget returns the slice the loop writes and the offset it writes at.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _StoreTarget(assign *ast.AssignStmt, name string) (string, int, string) {
	index, ok := assign.Lhs[0].(*ast.IndexExpr)
	if !ok {
		return "", 0, "loop body does not store into a slice element"
	}

	slice, ok := index.X.(*ast.Ident)
	if !ok {
		return "", 0, "store target is not a plain slice"
	}

	offset, ok := _Offset(index.Index, name)
	if !ok {
		return "", 0, "store index is not the loop variable plus a constant"
	}

	return slice.Name, offset, ""
}

// _Collector gathers the slices and offsets one loop body reads.
type _Collector struct {
	name    string
	slices  []string
	offsets []int
	seen    map[string]bool
	marked  map[int]bool
	reason  string
}

// _LoadSet walks the right-hand side and returns the slices read and the offsets read at.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _LoadSet(expr ast.Expr, name string) ([]string, []int, string) {
	var (
		found = &_Collector{
			name:    name,
			slices:  nil,
			offsets: nil,
			seen:    make(map[string]bool),
			marked:  make(map[int]bool),
			reason:  "",
		}
	)

	ast.Inspect(expr, found._Visit)

	if found.reason != "" {
		return nil, nil, found.reason
	}

	if len(found.slices) == 0 {
		return nil, nil, "loop body reads no slice element"
	}

	_Sort(found.offsets)

	return found.slices, found.offsets, ""
}

// _Visit examines one node of the right-hand side.
//
// Revisions:
//   - 2026-09-23 02:12: initial creation
func (c *_Collector) _Visit(node ast.Node) bool {
	if c.reason != "" {
		return false
	}

	switch item := node.(type) {
	case *ast.IndexExpr:
		return c._Indexed(item)
	case *ast.BinaryExpr:
		if !LANE_OPERATORS[item.Op] {
			c.reason = fmt.Sprintf("operator %s has no lane-wise form here", item.Op)

			return false
		}
	case *ast.CallExpr:
		if !_IsConversion(item) {
			c.reason = "loop body calls a function, which cannot be split across lanes"

			return false
		}
	}

	return true
}

// _Indexed records one indexed read.
//
// Revisions:
//   - 2026-09-23 02:12: initial creation
func (c *_Collector) _Indexed(item *ast.IndexExpr) bool {
	slice, offset, why := _Load(item, c.name)
	if why != "" {
		c.reason = why

		return false
	}

	if !c.seen[slice] {
		c.seen[slice] = true
		c.slices = append(c.slices, slice)
	}

	if !c.marked[offset] {
		c.marked[offset] = true
		c.offsets = append(c.offsets, offset)
	}

	return false
}

// _Load reads one indexed expression from the right-hand side.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Load(index *ast.IndexExpr, name string) (string, int, string) {
	slice, ok := index.X.(*ast.Ident)
	if !ok {
		return "", 0, "a load is not from a plain slice"
	}

	offset, ok := _Offset(index.Index, name)
	if !ok {
		return "", 0, "a load index is not the loop variable plus a constant"
	}

	return slice.Name, offset, ""
}

// _Offset reads an index of the form "idx", "idx + k" or "idx - k".
//
// Anything else is refused. An index computed any other way may still be affine, but
// proving it needs the constant folding a compiler has and this does not, and an index this
// misreads places a lane's load at the wrong address.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Offset(expr ast.Expr, name string) (int, bool) {
	switch index := expr.(type) {
	case *ast.Ident:
		return 0, index.Name == name
	case *ast.BinaryExpr:
		if index.Op != token.ADD && index.Op != token.SUB {
			return 0, false
		}

		ident, ok := index.X.(*ast.Ident)
		if !ok || ident.Name != name {
			return 0, false
		}

		literal, ok := index.Y.(*ast.BasicLit)
		if !ok || literal.Kind != token.INT {
			return 0, false
		}

		value, err := strconv.Atoi(literal.Value)
		if err != nil {
			return 0, false
		}

		if index.Op == token.SUB {
			value = -value
		}

		return value, true
	default:
		return 0, false
	}
}

// CARRIED_DEPENDENCE reports a loop whose store feeds its own earlier-indexed loads.
const (
	CARRIED_DEPENDENCE = "%s is read at %+d and written at %+d, so a lane would read " +
		"what the scalar loop had already overwritten"
)

// _Dependence rejects a loop whose store feeds its own later loads.
//
// When the loop writes and reads the same slice, the sign of the offset decides everything.
// Reading behind the store means a lane would read an element the scalar loop had already
// overwritten, and a vector kernel reads the original instead - the results differ, and
// nothing about the code says so. Reading at or ahead of the store is safe, because those
// elements are still original when the block is loaded.
//
// Two different names are assumed not to alias. That assumption cannot be discharged here:
// whether dst and src are the same memory is decided by the caller, and a syntactic pass
// cannot see the call. It is stated in the verdict rather than hidden.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Dependence(store string, offset int, loads []string, stencil []int) string {
	for _, slice := range loads {
		if slice != store {
			continue
		}

		for _, read := range stencil {
			if read < offset {
				return fmt.Sprintf(CARRIED_DEPENDENCE, slice, read, offset)
			}
		}
	}

	return ""
}

// _IsConversion reports whether a call is a conversion to a builtin numeric type.
//
// A conversion is allowed because it is not a call at all once compiled - it is a width
// change, which every lane does independently. Anything else is refused, including the
// builtins, because len and cap are loop-invariant but min, max and the rest are not
// uniformly lane-wise and telling them apart needs types.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _IsConversion(call *ast.CallExpr) bool {
	const CONVERSION_ARGUMENTS = 1

	ident, ok := call.Fun.(*ast.Ident)
	if !ok || len(call.Args) != CONVERSION_ARGUMENTS {
		return false
	}

	switch ident.Name {
	case "byte", "rune", "uint", "uint8", "uint16", "uint32", "uint64",
		"int", "int8", "int16", "int32", "int64":
		return true
	default:
		return false
	}
}

// _Sort orders a small offset set. It is an insertion sort because a stencil has a handful
// of entries and the standard library's comparison form would cost an import for it.
//
// Revisions:
//   - 2026-09-23 01:15: initial creation
func _Sort(values []int) {
	for idx := 1; idx < len(values); idx++ {
		for back := idx; back > 0 && values[back] < values[back-1]; back-- {
			values[back], values[back-1] = values[back-1], values[back]
		}
	}
}
