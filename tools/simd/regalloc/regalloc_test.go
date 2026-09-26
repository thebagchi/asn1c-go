package regalloc_test

import (
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/tools/simd/regalloc"
)

// The registers Go's ABI keeps for itself. A context that hands one of these to a kernel
// produces a fault somewhere else entirely - the goroutine pointer is gone, or the
// assembler's scratch is overwritten between two instructions it expanded - so this is
// checked by name rather than trusted to the bounds arithmetic that builds the files.
var (
	AMD64_RESERVED = []string{"Y15", "R14", "SP", "BP", "R15"}
	ARM64_RESERVED = []string{
		"R18", "R26", "R27", "R28", "R29", "R30",
		"V8", "V9", "V10", "V11", "V12", "V13", "V14", "V15",
	}
)

// TestSpellingsAgree is the invariant the whole type exists for.
//
// A kernel names a register twice: by name for an ordinary instruction and by number for an
// encoding macro, which computes its prefix arithmetically and cannot do arithmetic on a
// name. Nothing in the assembler connects the two, so "VMOVDQU (AX), Y4" beside
// "VPADDB_256(N_SRC, N_DST, N_TMP)" assembles cleanly whatever the numbers say and reads
// the wrong registers at run time. Both spellings coming from one allocation is what makes
// that unwritable.
func TestSpellingsAgree(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		context func(string) *regalloc.Context
		prefix  string
	}{
		{name: "amd64", context: regalloc.NewAmd64, prefix: "Y"},
		{name: "arm64", context: regalloc.NewArm64, prefix: "V"},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			context := item.context("probe")

			for idx := range 6 {
				value, err := context.Vector("v" + string(rune('a'+idx)))
				if err != nil {
					t.Fatalf("take %d: %v", idx, err)
				}

				want := item.prefix + _Digits(value.Number())
				if value.Register() == want {
					continue
				}

				t.Errorf(
					"%s is register %s but number %d, spelling %s",
					value.Name(), value.Register(), value.Number(), want,
				)
			}
		})
	}
}

// TestReservedRegistersAreNeverLent checks that the files withhold what the ABI owns.
func TestReservedRegistersAreNeverLent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		context  *regalloc.Context
		reserved []string
	}{
		{name: "amd64", context: regalloc.NewAmd64("probe"), reserved: AMD64_RESERVED},
		{name: "arm64", context: regalloc.NewArm64("probe"), reserved: ARM64_RESERVED},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			handed := _Drain(t, item.context)

			for _, name := range item.reserved {
				if handed[name] {
					t.Errorf("%s was handed out; the ABI reserves it", name)
				}
			}
		})
	}
}

// TestExhaustionIsAnError checks that running out is reported rather than wrapping round.
//
// Silently reusing a live register is the one failure that would make the type worse than
// no type at all: a caller that trusted it would have two values in one register and no
// reason to suspect it.
func TestExhaustionIsAnError(t *testing.T) {
	t.Parallel()

	context := regalloc.NewAmd64("probe")
	handed := _Drain(t, context)

	if len(handed) == 0 {
		t.Fatal("no registers were handed out at all")
	}

	if free := context.Free(regalloc.VECTOR); free != 0 {
		t.Fatalf("drained the file but %d vectors are still free", free)
	}

	if _, err := context.Vector("overflow"); err == nil {
		t.Fatal("took a vector from an empty file")
	}
}

// TestReleaseReturnsTheRegister checks that a freed register is handed out again.
func TestReleaseReturnsTheRegister(t *testing.T) {
	t.Parallel()

	context := regalloc.NewAmd64("probe")

	first, err := context.Vector("first")
	if err != nil {
		t.Fatalf("take: %v", err)
	}

	if err := context.Release(first); err != nil {
		t.Fatalf("release: %v", err)
	}

	second, err := context.Vector("second")
	if err != nil {
		t.Fatalf("retake: %v", err)
	}

	if second.Register() != first.Register() {
		t.Errorf("released %s but got %s", first.Register(), second.Register())
	}

	if err := context.Release(first); err == nil {
		t.Error("released the same value twice")
	}
}

// TestDuplicateNameIsRejected checks that one name cannot mean two registers.
func TestDuplicateNameIsRejected(t *testing.T) {
	t.Parallel()

	context := regalloc.NewAmd64("probe")

	if _, err := context.Vector("src"); err != nil {
		t.Fatalf("take: %v", err)
	}

	if _, err := context.Vector("src"); err == nil {
		t.Error("bound the same name twice")
	}
}

// TestHeaderCarriesBothSpellings checks what a kernel actually includes.
func TestHeaderCarriesBothSpellings(t *testing.T) {
	t.Parallel()

	context := regalloc.NewAmd64("shift")

	src, err := context.Vector("SRC")
	if err != nil {
		t.Fatalf("take: %v", err)
	}

	header := context.Header()

	for _, want := range []string{
		"DO NOT EDIT",
		"#define SRC",
		"#define N_SRC",
		src.Register(),
	} {
		if !strings.Contains(header, want) {
			t.Errorf("header does not mention %q:\n%s", want, header)
		}
	}
}

// _Drain takes every register of both kinds and returns the spellings handed out.
func _Drain(t *testing.T, context *regalloc.Context) map[string]bool {
	t.Helper()

	var (
		handed = make(map[string]bool)
		idx    int
	)

	for {
		value, err := context.Vector("v" + _Digits(idx))
		if err != nil {
			break
		}

		handed[value.Register()] = true
		idx++
	}

	for {
		value, err := context.Scalar("s" + _Digits(idx))
		if err != nil {
			break
		}

		handed[value.Register()] = true
		idx++
	}

	return handed
}

// _Digits renders a small number without pulling in a formatter.
func _Digits(value int) string {
	const BASE = 10

	if value < BASE {
		return string(rune('0' + value))
	}

	return _Digits(value/BASE) + string(rune('0'+value%BASE))
}
