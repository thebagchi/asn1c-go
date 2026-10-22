// Command sde runs a program with a CPU feature this processor may lack.
//
// Intel SDE emulates the feature when this processor does not have it.
// The kit is the Intel Simplified Software License (23 August 2023).
// The download is a build artefact. .tools/cmd/sde/downloads and
// .tools/cmd/sde/kit stay out of git. A later run fetches the same pin.
//
// The pin is SDE 10.13.1, the Linux kit of 28 July 2026. The bytes are checked
// against SHA256 before the archive is unpacked. The unpacked tree is left as
// Intel shipped it. The standard library has no xz reader, so unpacking uses
// the system tar.
//
//	go run ./.tools/cmd/sde
//	go run ./.tools/cmd/sde install
//	go run ./.tools/cmd/sde -feature avx512 -- go test -count=1
//	go run ./.tools/cmd/sde -feature avx512 -count -- go test -bench .
//
// -feature is avx2, avx512, or gfni. avx2 selects Haswell. avx512 and gfni
// select Ice Lake, which has AVX512BW. When this CPU has the feature, the
// program runs on this CPU. -count always uses SDE and writes sde-mix-out.txt.
// A time from that run is the time of the emulator.
//
// With no arguments the command installs the kit, when it is absent, and
// prints the path of the sde program.
//
// SDE attaches with ptrace. On Ubuntu and on WSL that requires
// kernel.yama.ptrace_scope to be 0. This command does not change that setting.
package main
