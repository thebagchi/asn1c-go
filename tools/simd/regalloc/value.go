package regalloc

import (
	"fmt"
)

// Value is one register a kernel has taken out of a Context.
//
// It carries both spellings of the same register, and that is the whole reason the type
// exists. Go's assembler names a vector register Y3; the VEX macros in tools/simd/macro take the
// number 3, because they compute the encoding arithmetically and cannot do arithmetic on a
// name. A kernel therefore writes the register two different ways, and nothing in the
// assembler connects them: "VMOVDQU (AX), Y4" beside "VPADDB_256(N_SRC, N_DST, N_TMP)"
// assembles cleanly whatever the numbers are, and reads the wrong registers at run time.
//
// Taking both from one allocation is what makes that impossible to write.
type Value struct {
	name     string
	register string
	number   int
	kind     Kind
}

// Kind is the register file a value was taken from.
type Kind int

// The register files a Context allocates from.
const (
	VECTOR Kind = iota
	SCALAR
)

// String names a register file.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (k Kind) String() string {
	if k == VECTOR {
		return "vector"
	}

	return "scalar"
}

// Name is what the kernel calls this value.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (v *Value) Name() string {
	return v.name
}

// Register is the spelling Go's assembler takes, such as "Y3" or "AX".
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (v *Value) Register() string {
	return v.register
}

// Number is the spelling the encoding macros take, such as 3.
//
// It is the same register Register names. A caller that uses one without the other is the
// failure this type prevents, so both come from here and neither is written by hand.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (v *Value) Number() int {
	return v.number
}

// Kind is the register file this value came from.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (v *Value) Kind() Kind {
	return v.kind
}

// String renders a value for a diagnostic.
//
// Revisions:
//   - 2026-09-23 02:40: initial creation
func (v *Value) String() string {
	return fmt.Sprintf("%s=%s(%d)", v.name, v.register, v.number)
}
