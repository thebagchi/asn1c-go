package common

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Git runs git in dir and returns its standard output.
// A non-zero status is an error, and the error holds the standard error text.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func Git(
	dir string,
	args ...string,
) (string, error) {
	cmd := exec.Command(
		"git",
		args...,
	)
	cmd.Dir = dir

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf(
			"git %s: %w: %s",
			strings.Join(
				args,
				" ",
			),
			err,
			strings.TrimSpace(
				stderr.String(),
			),
		)
	}

	return stdout.String(), nil
}
