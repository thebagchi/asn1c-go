//go:build !linux

// Command sde is the Linux kit. On any other system it stops.
package main

import (
	"fmt"
	"os"
)

// main reports that this system cannot run the Linux kit.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func main() {
	fmt.Fprintln(
		os.Stderr,
		"sde: the linux kit only",
	)
	os.Exit(1)
}
