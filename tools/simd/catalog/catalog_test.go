package catalog_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	AMD64_TABLE = "amd64.tsv"
	ARM64_TABLE = "arm64.tsv"
	WORD_BITS   = 32
	ABSENT      = "-"
	FULL_MASK   = uint32(0xFFFFFFFF)
)

// The arm64 instructions the encoding check assembles. Each is written the way Go's
// assembler takes it, and the operands are arbitrary: the check is that the bits the
// catalogue calls fixed come back unchanged, which no choice of register can affect.
//
// They are chosen to cover the shapes the merge has to get right - a branch, a scalar
// floating-point form, a vector form, a crypto form that takes no V prefix, and a load -
// because those are the rows where an encoding can be filed under the wrong mnemonic
// without anything else noticing.
var (
	ARM64_SAMPLES = []struct {
		mnemonic string
		source   string
	}{
		{mnemonic: "VADD", source: "VADD V2.B16, V1.B16, V0.B16"},
		{mnemonic: "VEOR", source: "VEOR V2.B16, V1.B16, V0.B16"},
		{mnemonic: "VLD1", source: "VLD1 (R1), [V0.B16]"},
		{mnemonic: "VST1", source: "VST1 [V0.B16], (R1)"},
		{mnemonic: "AESE", source: "AESE V1.B16, V0.B16"},
		{mnemonic: "SHA256H", source: "SHA256H V2.S4, V1, V0"},
		{mnemonic: "FADDD", source: "FADDD F2, F1, F0"},
		{mnemonic: "FADDS", source: "FADDS F2, F1, F0"},
		{mnemonic: "FCMPD", source: "FCMPD F1, F0"},
		{mnemonic: "ASR", source: "ASR R2, R1, R0"},
		{mnemonic: "ADD", source: "ADD R2, R1, R0"},
		{mnemonic: "MOVD", source: "MOVD (R1), R0"},
		{mnemonic: "MOVWU", source: "MOVWU (R1), R0"},
		{mnemonic: "MOVW", source: "MOVW (R1), R0"},
		{mnemonic: "MOVBU", source: "MOVBU (R1), R0"},
		{mnemonic: "MOVHU", source: "MOVHU (R1), R0"},
		{mnemonic: "FMOVD", source: "FMOVD (R1), F0"},
		{mnemonic: "FMOVS", source: "FMOVS (R1), F0"},
		{mnemonic: "JMP", source: "JMP 2(PC)"},
	}
)

// Row is one line of a catalogue, keyed by column name.
type Row map[string]string

// TestArm64EncodingMatchesAssembler assembles each sample and checks that the bits the
// catalogue calls fixed survive unchanged.
//
// The invariant is deliberately operand-blind. Checking a whole instruction word would need
// this test to know which field each register lands in, which is the same knowledge the
// catalogue is claiming to hold - so it would be checking the table against itself. Masking
// the operands away leaves only what the table asserts independently: that this mnemonic
// encodes to this opcode. That is what caught the vector FADD encoding filed under scalar
// FADDS, where the row was internally consistent and simply described a different
// instruction.
func TestArm64EncodingMatchesAssembler(t *testing.T) {
	t.Parallel()

	rows := _Load(t, ARM64_TABLE)

	for _, sample := range ARM64_SAMPLES {
		t.Run(sample.mnemonic, func(t *testing.T) {
			t.Parallel()

			forms, ok := rows[sample.mnemonic]
			if !ok {
				t.Fatalf("%s is not in the catalogue", sample.mnemonic)
			}

			var (
				word  = _Assemble(t, sample.source)
				tried []string
			)

			for _, form := range forms {
				if form["MASK"] == "0x00000000" {
					continue
				}

				var (
					mask = _Word(t, form["MASK"])
					base = _Word(t, form["BASE"])
				)

				if word&mask == base {
					return
				}

				tried = append(tried, fmt.Sprintf(
					"%s (%s)", form["BASE"], form["VARIANT"],
				))
			}

			if len(tried) == 0 {
				t.Skipf("%s has no encoding in the catalogue", sample.mnemonic)
			}

			t.Errorf(
				"%s assembles to 0x%08X, which matches none of: %s",
				sample.source, word, strings.Join(tried, ", "),
			)
		})
	}
}

// TestArm64FieldsFillTheMask checks every row's operand fields against its mask.
//
// An arm64 instruction is exactly one word, so the fixed bits and the operand fields
// partition 32 bits between them with nothing left over. A row where they do not is a row
// whose bit pattern was misread, and every byte it would go on to produce is wrong.
func TestArm64FieldsFillTheMask(t *testing.T) {
	t.Parallel()

	for name, forms := range _Load(t, ARM64_TABLE) {
		for _, row := range forms {
			if row["FIELDS"] == ABSENT {
				continue
			}

			var (
				mask  = _Word(t, row["MASK"])
				base  = _Word(t, row["BASE"])
				width = _FieldWidth(t, row["FIELDS"])
				free  = WORD_BITS - _Ones(mask)
			)

			if width != free {
				t.Errorf(
					"%s: fields are %d bits, mask leaves %d free",
					name, width, free,
				)
			}

			if base&^mask != 0 {
				t.Errorf(
					"%s: base 0x%08X sets bits outside mask 0x%08X",
					name, base, mask,
				)
			}
		}
	}
}

// TestAmd64SpecIsWellFormed checks that every encoding the amd64 table carries parses.
//
// A row whose opcode bytes do not read back as bytes cannot be hand-encoded from, which is
// the one thing the table exists for, so a malformed spec is a defect rather than a
// cosmetic problem.
func TestAmd64SpecIsWellFormed(t *testing.T) {
	t.Parallel()

	var (
		notation = regexp.MustCompile(`^E?VEX\.[0-9A-Z.]+$`)
		checked  int
	)

	for name, forms := range _Load(t, AMD64_TABLE) {
		for _, row := range forms {
			if row["CLASS"] != "vex" && row["CLASS"] != "evex" {
				continue
			}

			head, rest, found := strings.Cut(row["SPEC"], " ")
			if !found {
				t.Errorf("%s: spec %q has no opcode", name, row["SPEC"])

				continue
			}

			if !notation.MatchString(head) {
				t.Errorf("%s: %q is not Intel VEX notation", name, head)
			}

			for _, item := range strings.Fields(rest) {
				if _, err := strconv.ParseUint(item, 16, 8); err != nil {
					t.Errorf("%s: opcode %q is not a byte", name, item)
				}
			}

			checked++
		}
	}

	if checked == 0 {
		t.Fatal("no AVX rows in the amd64 catalogue")
	}
}

// TestGoPseudoOpsArePresent guards the shared instruction table.
//
// CALL, JMP, RET and NOP live in obj rather than in either architecture's anames.go. A
// catalogue built from the architecture file alone reports the four most common
// instructions in any kernel as unsupported, and it does so silently.
func TestGoPseudoOpsArePresent(t *testing.T) {
	t.Parallel()

	for _, table := range []string{AMD64_TABLE, ARM64_TABLE} {
		t.Run(table, func(t *testing.T) {
			t.Parallel()

			rows := _Load(t, table)

			for _, name := range []string{"CALL", "JMP", "RET", "NOP"} {
				if _, ok := rows[name]; !ok {
					t.Errorf("%s is missing from %s", name, table)
				}
			}
		})
	}
}

// _Assemble runs one instruction through Go's arm64 assembler and returns the word it
// produced. It cross-compiles, so it needs no arm64 machine.
//
// The probe ends in two returns rather than one so a forward branch has somewhere in range
// to land. With a single return the branch points past the end of the function and the
// assembler rejects it before producing any encoding at all.
func _Assemble(t *testing.T, source string) uint32 {
	t.Helper()

	var (
		dir  = t.TempDir()
		body = "TEXT ·probe(SB), NOSPLIT, $0-0\n\t%s\n\tRET\n\tRET\n"
		text = "#include \"textflag.h\"\n\n" + fmt.Sprintf(body, source)
	)

	_WriteAll(t, dir, map[string]string{
		"go.mod":        "module probe\n\ngo 1.26\n",
		"probe.go":      "package main\n\nfunc probe()\n\nfunc main() { probe() }\n",
		"probe_arm64.s": text,
	})

	build := exec.Command("go", "build", "-o", filepath.Join(dir, "probe.bin"), ".")
	build.Dir = dir

	build.Env = append(os.Environ(), "GOARCH=arm64", "GOOS=linux")

	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("assemble %q: %v\n%s", source, err, out)
	}

	return _Disassemble(t, dir, filepath.Join(dir, "probe.bin"))
}

// _Disassemble returns the first instruction word of the probe function.
func _Disassemble(t *testing.T, dir, binary string) uint32 {
	t.Helper()

	dump := exec.Command("go", "tool", "objdump", "-s", `main\.probe`, binary)
	dump.Dir = dir

	out, err := dump.CombinedOutput()
	if err != nil {
		t.Fatalf("objdump: %v\n%s", err, out)
	}

	var (
		word = regexp.MustCompile(`\t([0-9a-f]{8})\t`)
	)

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "probe_arm64.s:4") {
			continue
		}

		match := word.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		return _Word(t, "0x"+match[1])
	}

	t.Fatalf("no instruction word in objdump output:\n%s", out)

	return 0
}

// _WriteAll writes a set of files into one directory.
func _WriteAll(t *testing.T, dir string, files map[string]string) {
	t.Helper()

	const MODE = 0o600

	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), MODE); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// _Load reads a catalogue into rows grouped by mnemonic.
//
// A mnemonic has as many rows as it has encoding forms - Go spells every arm64 load and
// store MOV - so this groups rather than indexes. Indexing would silently keep whichever
// form happened to come last, and a check written against it would be testing one arbitrary
// encoding while appearing to test them all.
func _Load(t *testing.T, name string) map[string][]Row {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var (
		rows    = make(map[string][]Row)
		columns []string
	)

	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "\t")

		if columns == nil {
			columns = fields

			continue
		}

		row := make(Row, len(columns))
		for idx, column := range columns {
			if idx < len(fields) {
				row[column] = fields[idx]
			}
		}

		rows[fields[0]] = append(rows[fields[0]], row)
	}

	if len(rows) == 0 {
		t.Fatalf("%s has no rows", name)
	}

	return rows
}

// _Word parses a hex column.
func _Word(t *testing.T, text string) uint32 {
	t.Helper()

	value, err := strconv.ParseUint(strings.TrimPrefix(text, "0x"), 16, WORD_BITS)
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}

	return uint32(value)
}

// _FieldWidth totals the widths a FIELDS column declares.
func _FieldWidth(t *testing.T, fields string) int {
	t.Helper()

	var (
		total int
	)

	for _, item := range strings.Split(fields, ",") {
		_, size, found := strings.Cut(item, ":")
		if !found {
			t.Fatalf("field %q has no width", item)
		}

		width, err := strconv.Atoi(size)
		if err != nil {
			t.Fatalf("width of %q: %v", item, err)
		}

		total += width
	}

	return total
}

// _Ones counts the set bits of a mask.
func _Ones(mask uint32) int {
	var (
		count int
	)

	for bit := mask; bit != 0; bit >>= 1 {
		count += int(bit & 1)
	}

	return count
}
