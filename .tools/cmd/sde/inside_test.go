//go:build linux

package main

import (
	"path/filepath"
	"testing"
)

// This file is an internal test because _Inside is unexported.

// TestInside_KeepsMembersInRoot checks the archive path guard. A member that
// climbs out of the kit directory, or that is absolute, is refused.
//
// Revisions:
//   - 2026-10-21 21:37: initial creation
func TestInside_KeepsMembersInRoot(t *testing.T) {
	var (
		root = t.TempDir()
		rows = []*struct {
			name   string
			inside bool
		}{
			{
				name:   "sde-external/sde",
				inside: true,
			},
			{
				name:   "./sde-external/sde",
				inside: true,
			},
			{
				name:   "",
				inside: false,
			},
			{
				name:   "../sde",
				inside: false,
			},
			{
				name:   "kit/../../etc/passwd",
				inside: false,
			},
			{
				name: filepath.Join(
					root,
					"sde",
				),
				inside: false,
			},
		}
	)

	for _, row := range rows {
		t.Run(
			row.name,
			func(t *testing.T) {
				got := _Inside(
					root,
					row.name,
				)
				if got != row.inside {
					t.Fatalf(
						"_Inside(%q) = %t, want %t",
						row.name,
						got,
						row.inside,
					)
				}
			},
		)
	}
}
