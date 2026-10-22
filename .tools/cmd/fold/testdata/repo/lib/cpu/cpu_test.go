package cpu_test

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/cpu"
)

// CPUINFO is where Linux publishes the processor's own feature list, which
// makes it an oracle the detection code did not write.
const (
	CPUINFO = "/proc/cpuinfo"
)

// TestFlagsImplyEachOther checks the order the flags must stand in: a wider
// extension is never reported without the narrower one it builds on.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func TestFlagsImplyEachOther(t *testing.T) {
	t.Parallel()

	if cpu.HAS_AVX2 && !cpu.HAS_SSE2 {
		t.Error("AVX2 without SSE2")
	}

	if cpu.HAS_AVX512 && !cpu.HAS_AVX2 {
		t.Error("AVX-512 without AVX2")
	}

	if cpu.HAS_GFNI && !cpu.HAS_AVX2 {
		t.Error("GFNI reported without the AVX2 its 256-bit forms need")
	}

	t.Logf("vector: %s, gfni: %v", cpu.Vector(), cpu.HAS_GFNI)
}

// TestFlagsMatchTheKernelsReport compares the detection against the feature
// words Linux prints for the processor, so a wrong CPUID bit or XCR0 mask is
// caught by something that reads neither.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func TestFlagsMatchTheKernelsReport(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("no %s to compare against on %s/%s", CPUINFO, runtime.GOOS, runtime.GOARCH)
	}

	flags := flagsFromCPUInfo(t)

	cases := []struct {
		name string
		flag string
		have bool
	}{
		{name: "avx2", flag: "avx2", have: cpu.HAS_AVX2},
		{name: "avx512", flag: "avx512bw", have: cpu.HAS_AVX512},
		{name: "gfni", flag: "gfni", have: cpu.HAS_GFNI},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()

			if want := flags[item.flag]; item.have != want {
				t.Errorf("detected %v, %s says %v", item.have, CPUINFO, want)
			}
		})
	}
}

// flagsFromCPUInfo reads the first processor's feature words.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func flagsFromCPUInfo(t *testing.T) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(CPUINFO)
	if err != nil {
		t.Skipf("read %s: %v", CPUINFO, err)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != "flags" {
			continue
		}

		flags := make(map[string]bool)
		for _, word := range strings.Fields(rest) {
			flags[word] = true
		}

		return flags
	}

	t.Skipf("%s has no flags line", CPUINFO)

	return nil
}
