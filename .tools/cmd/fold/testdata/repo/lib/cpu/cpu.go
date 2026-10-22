// Package cpu reports what the processor can run, decided once at start-up, so
// that every package with a choice of kernels asks the same question and gets
// the same answer.
//
// The flags are variables on amd64, set from CPUID and XCR0 before any package
// that imports this one initialises, and constants everywhere else. A kernel
// needs both sources: the feature bit says the processor has the instructions,
// and XCR0 says the operating system saves the registers they use across a
// context switch. Without the second, the first is permission to corrupt
// whatever process runs next.
package cpu

// Vector names the widest vector extension this processor can run, for a log
// line or a test name.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func Vector() string {
	switch {
	case HAS_AVX512:
		return "avx512"
	case HAS_AVX2:
		return "avx2"
	case HAS_SSE2:
		return "sse2"
	default:
		return "none"
	}
}
