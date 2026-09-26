//go:build ignore

// Command gen builds the two probes feature detection reads: CPUID, which says
// what the processor has, and XGETBV, which says what register state the
// operating system saves across a context switch. Both are needed: a feature
// bit alone is not permission to use the registers behind it.
//
// avo builds them, so the two dozen lines of assembly are reviewed as the Go
// that produced them. Regenerate with "make generate".
package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/reg"
)

// main emits both probes.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation, from lib/bitbuffer/gen
func main() {
	ConstraintExpr("amd64")

	_CPUID()
	_XGetBV()

	Generate()
}

// _CPUID exposes the CPUID instruction, so feature detection is written in Go.
//
// The results are unnamed, so the frame slots the assembly stores to match a
// declaration that follows the no-named-returns rule.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
//   - 2026-09-24 01:40: moved here from lib/bitbuffer/gen
func _CPUID() {
	TEXT("_CPUID", NOSPLIT, "func(leaf, sub uint32) (uint32, uint32, uint32, uint32)")
	Doc("_CPUID returns the four registers CPUID fills for the given leaf and subleaf.")

	Load(Param("leaf"), EAX)
	Load(Param("sub"), ECX)
	CPUID()
	Store(EAX, ReturnIndex(0))
	Store(EBX, ReturnIndex(1))
	Store(ECX, ReturnIndex(2))
	Store(EDX, ReturnIndex(3))
	RET()
}

// _XGetBV reads XCR0.
//
// Revisions:
//   - 2026-09-23 03:52: initial creation
//   - 2026-09-24 01:40: moved here from lib/bitbuffer/gen
func _XGetBV() {
	TEXT("_XGetBV", NOSPLIT, "func() (uint32, uint32)")
	Doc("_XGetBV returns the two halves of XCR0.")

	XORL(ECX, ECX)
	XGETBV()
	Store(EAX, ReturnIndex(0))
	Store(EDX, ReturnIndex(1))
	RET()
}
