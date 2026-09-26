// Package regalloc hands a kernel its registers, so that nothing in the kernel names one by
// hand.
//
// It is the part of avo worth keeping. Composing a kernel from assembler macros costs
// nothing and reads well - tools/simd/macro shows that - but it gives up the one thing avo does
// that a preprocessor cannot: knowing which registers are in use. The preprocessor has no
// state. It cannot count, cannot remember that Y3 is live, and cannot refuse when a second
// value is put there.
//
// Two mistakes follow from that, and neither one fails to assemble:
//
//   - **The two spellings drift.** The encoding macros take a register number because they
//     compute the VEX prefix arithmetically; every other instruction takes a name. Writing
//     Y4 in one line and 2 in the next assembles cleanly and reads the wrong register.
//   - **X<n> and Y<n> are the same register.** A shift count put in X2 destroys whatever
//     Y2 was holding. This one cost real time in the avo kernel this repository already
//     has, and it is invisible in the source: the two lines do not mention each other.
//
// A Context answers both. One allocation yields one index, both spellings come from it, and
// a register that is live cannot be handed out again. What it emits is a header of
// #defines, so the kernel names values and never registers.
//
// It is not a register allocator in the compiler sense. There is no liveness analysis, no
// spilling and no graph colouring: a kernel small enough to write as macros has fewer live
// values than the machine has registers, and if it does not, it wants avo or a compiler.
// This is a bookkeeper, and bookkeeping is what was missing.
package regalloc

import (
	"fmt"
	"strings"
)

// The bounds of each register file, named because a bare 15 beside a bare 16 says nothing
// about which one is a count and which one is the first register withheld.
const (
	AMD64_VECTOR_COUNT = 15 // Y0 to Y14; X15 is the ABI's zero register
	ARM64_SAVED_FIRST  = 8  // V8 to V15 are callee-saved, so they are not lent out
	ARM64_SAVED_AFTER  = 16
	ARM64_VECTOR_COUNT = 32
	ARM64_SCALAR_COUNT = 18 // R0 to R17; R18 and above are reserved or callee-saved
)

// AMD64_VECTORS and the three that follow are the registers each architecture lends out.
//
// The reservations are from Go's own ABI description rather than from convention: amd64
// keeps R14 for the current goroutine and X15 as a zero register, and arm64 keeps R18 for
// the platform, R26 for the closure context, R27 as the assembler's own scratch and R28 for
// the current goroutine. Handing any of those to a kernel produces a fault somewhere else
// entirely, long after the instruction that caused it.
var (
	AMD64_VECTORS = _Range("Y", 0, AMD64_VECTOR_COUNT)
	AMD64_SCALARS = []string{
		"AX", "BX", "CX", "DX", "SI", "DI",
		"R8", "R9", "R10", "R11", "R12", "R13",
	}

	ARM64_VECTORS = append(
		_Range("V", 0, ARM64_SAVED_FIRST),
		_Range("V", ARM64_SAVED_AFTER, ARM64_VECTOR_COUNT)...,
	)
	ARM64_SCALARS = _Range("R", 0, ARM64_SCALAR_COUNT)
)

// Context is the set of registers one kernel has, and which of them are in use.
type Context struct {
	name    string
	arch    string
	banks   map[Kind]*_Bank
	live    map[string]*Value
	order   []string
	comment string
}

// _Bank is one register file and the registers still free in it.
type _Bank struct {
	spellings []string
	taken     []bool
}

// NewAmd64 returns a context over the amd64 registers a kernel may use.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func NewAmd64(name string) *Context {
	return _New(name, "amd64", AMD64_VECTORS, AMD64_SCALARS)
}

// NewArm64 returns a context over the arm64 registers a kernel may use.
//
// V8 to V15 are withheld as well as the reserved scalars. The procedure call standard makes
// the low 64 bits of those callee-saved, so a kernel that uses one owes its caller a save
// and a restore - which a kernel composed from macros has no good place to put.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func NewArm64(name string) *Context {
	return _New(name, "arm64", ARM64_VECTORS, ARM64_SCALARS)
}

// _New builds a context over two register files.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func _New(name, arch string, vectors, scalars []string) *Context {
	return &Context{
		name: name,
		arch: arch,
		banks: map[Kind]*_Bank{
			VECTOR: _NewBank(vectors),
			SCALAR: _NewBank(scalars),
		},
		live:    make(map[string]*Value),
		order:   nil,
		comment: "",
	}
}

// _NewBank builds one register file.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func _NewBank(spellings []string) *_Bank {
	return &_Bank{
		spellings: spellings,
		taken:     make([]bool, len(spellings)),
	}
}

// Vector takes a vector register and binds it to a name.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) Vector(name string) (*Value, error) {
	return c._Take(name, VECTOR)
}

// Scalar takes a general-purpose register and binds it to a name.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) Scalar(name string) (*Value, error) {
	return c._Take(name, SCALAR)
}

// Release returns a value's register to its file, so a later allocation may reuse it.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) Release(value *Value) error {
	if value == nil {
		return fmt.Errorf("%s: released a nil value", c.name)
	}

	held, ok := c.live[value.name]
	if !ok {
		return fmt.Errorf("%s: %s is not live", c.name, value.name)
	}

	if held != value {
		return fmt.Errorf("%s: %s was rebound since it was taken", c.name, value.name)
	}

	delete(c.live, value.name)
	c.banks[value.kind].taken[value.number] = false

	return nil
}

// Live returns the values currently held, in the order they were taken.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) Live() []*Value {
	var (
		found = make([]*Value, 0, len(c.live))
	)

	for _, name := range c.order {
		if value, ok := c.live[name]; ok {
			found = append(found, value)
		}
	}

	return found
}

// Free reports how many registers of one kind remain.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) Free(kind Kind) int {
	var (
		count int
	)

	for _, taken := range c.banks[kind].taken {
		if !taken {
			count++
		}
	}

	return count
}

// Header renders the bindings as an assembler header.
//
// Each value becomes two defines, the name for ordinary instructions and N_<name> for the
// encoding macros, because those take a number. They are written together from one
// allocation, which is the point: a kernel that uses only these two spellings cannot put
// its data in one register and its instruction in another.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) Header() string {
	var (
		text  strings.Builder
		width = c._Width()
	)

	fmt.Fprintf(&text, "// Code generated by tools/simd/regalloc. DO NOT EDIT.\n//\n")
	fmt.Fprintf(&text, "// Register bindings for %s, on %s.\n", c.name, c.arch)
	fmt.Fprintf(&text, "//\n// Use the name for an instruction and N_<name> for an ")
	fmt.Fprintf(&text, "encoding macro. They are\n// the same register.\n\n")

	for _, value := range c.Live() {
		fmt.Fprintf(&text, "#define %-*s %s\n", width, value.name, value.register)
		fmt.Fprintf(&text, "#define %-*s %d\n", width, "N_"+value.name, value.number)
	}

	return text.String()
}

// _Take binds a name to a free register of one kind.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) _Take(name string, kind Kind) (*Value, error) {
	if name == "" {
		return nil, fmt.Errorf("%s: a value needs a name", c.name)
	}

	if _, clash := c.live[name]; clash {
		return nil, fmt.Errorf("%s: %s is already live", c.name, name)
	}

	bank := c.banks[kind]

	index, err := bank._First()
	if err != nil {
		return nil, fmt.Errorf("%s: no %s register for %s: %w", c.name, kind, name, err)
	}

	value := &Value{
		name:     name,
		register: bank.spellings[index],
		number:   index,
		kind:     kind,
	}

	bank.taken[index] = true
	c.live[name] = value
	c.order = append(c.order, name)

	return value, nil
}

// _Width is the longest define name, so the header aligns without hand spacing.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (c *Context) _Width() int {
	const PREFIX = 2

	var (
		width int
	)

	for _, value := range c.Live() {
		if len(value.name)+PREFIX > width {
			width = len(value.name) + PREFIX
		}
	}

	return width
}

// _First returns the lowest free register in a file.
//
// Lowest rather than least-recently-used, deliberately. A kernel's generated header is read
// beside its assembly, and a stable, dense assignment makes a diff of that header mean
// something: a register moving is a real change, not an artefact of allocation order.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (b *_Bank) _First() (int, error) {
	for index, taken := range b.taken {
		if !taken {
			return index, nil
		}
	}

	return 0, fmt.Errorf("all %d are live", len(b.spellings))
}

// _Range builds a run of register spellings.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func _Range(prefix string, from, until int) []string {
	var (
		names = make([]string, 0, until-from)
	)

	for index := from; index < until; index++ {
		names = append(names, fmt.Sprintf("%s%d", prefix, index))
	}

	return names
}
