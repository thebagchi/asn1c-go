//go:build linux

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// main runs the feature question, or installs the kit.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func main() {
	err := _Run(
		os.Args[1:],
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"%s: sde: %s\n",
			LEVEL_ERROR,
			err,
		)
		os.Exit(1)
	}
}

// _Run reads the flags, chooses native or SDE, and executes the program.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Run(args []string) error {
	ask, err := _Bind(args)
	if err != nil {
		return err
	}

	have, err := _Host(ask.feature)
	if err != nil {
		return err
	}

	step, err := _Decide(
		&_Known{
			ask:  ask,
			have: have,
		},
	)
	if err != nil {
		return err
	}

	return _Go(
		step,
		ask,
	)
}

// _Bind parses -feature and -count. The remaining arguments are the program.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Bind(args []string) (*_Ask, error) {
	set := flag.NewFlagSet(
		"sde",
		flag.ContinueOnError,
	)
	set.SetOutput(io.Discard)

	var (
		feature = set.String(
			"feature",
			"",
			"avx2, avx512, or gfni",
		)
		count = set.Bool(
			"count",
			false,
			"write the instruction mix through SDE",
		)
		err = set.Parse(args)
	)
	if err != nil {
		return nil, err
	}

	return &_Ask{
		feature: *feature,
		count:   *count,
		program: set.Args(),
	}, nil
}

// _Go installs, runs on this CPU, or runs under SDE.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Go(
	step *_Step,
	ask *_Ask,
) error {
	switch step.mode {
	case MODE_INSTALL:
		return _Show()
	case MODE_NATIVE:
		return _Native(ask)
	case MODE_SDE:
		return _Emulate(
			step,
			ask,
		)
	default:
		return fmt.Errorf(
			"unknown mode %s",
			step.mode,
		)
	}
}

// _Show installs the kit when it is absent, and prints the sde program path.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Show() error {
	binary, err := _Ready()
	if err != nil {
		return err
	}

	fmt.Println(binary)

	return nil
}

// _Native runs the program on this CPU. The time from this run is a CPU time.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Native(ask *_Ask) error {
	_Log(
		"native " + ask.feature,
	)

	return _ExecProgram(ask.program)
}

// _Emulate runs the program under the chip for the feature.
// -count adds the instruction mix. A time from this run is the emulator.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Emulate(
	step *_Step,
	ask *_Ask,
) error {
	binary, err := _Ready()
	if err != nil {
		return err
	}

	if err := _RequirePtrace(); err != nil {
		return err
	}

	_Log(
		"sde " + step.chip,
	)

	if step.mix {
		_Log(
			"mix file " + MIX_FILE,
		)
	}

	return _Exec(
		binary,
		_SDEArgs(
			step,
			ask.program,
		),
	)
}

// _Ready returns the sde program, after a download when the kit is absent.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Ready() (string, error) {
	dir, err := _Dir()
	if err != nil {
		return "", err
	}

	paths := &_Paths{
		downloads: filepath.Join(
			dir,
			"downloads",
		),
		kit: filepath.Join(
			dir,
			"kit",
		),
	}

	return _Install(paths)
}

// _SDEArgs is the chip, the optional mix file, and the program.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _SDEArgs(
	step *_Step,
	program []string,
) []string {
	args := []string{
		step.chip,
	}
	if step.mix {
		args = append(
			args,
			MIX_FLAG,
			MIX_FILE_FLAG,
			MIX_FILE,
		)
	}

	args = append(
		args,
		"--",
	)
	args = append(
		args,
		program...,
	)

	return args
}

// _ExecProgram replaces this process with the program. A name is found on PATH.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _ExecProgram(args []string) error {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	return _Exec(
		path,
		args[1:],
	)
}

// _Log writes one progress line to stderr.
//
// Revisions:
//   - 2026-10-21 22:17: initial creation
func _Log(text string) {
	fmt.Fprintf(
		os.Stderr,
		"%s: sde: %s\n",
		LEVEL_LOG,
		text,
	)
}
