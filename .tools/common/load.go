// Package common loads the packages that every gate reads.
package common

import (
	"fmt"

	"golang.org/x/tools/go/packages"
)

// Load reads the named packages from dir, and it reads their tests.
// Load refuses a package with an error, because its type information is not complete.
// An empty result is an error.
//
// Revisions:
//   - 2026-10-21 13:01: initial creation
func Load(
	dir string,
	patterns []string,
) ([]*packages.Package, error) {
	var (
		cfg = &packages.Config{
			Mode:  packages.LoadSyntax | packages.NeedModule,
			Dir:   dir,
			Tests: true,
		}
		pkgs, err = packages.Load(
			cfg,
			patterns...,
		)
	)
	if err != nil {
		return nil, fmt.Errorf(
			"load packages: %w",
			err,
		)
	}

	if len(
		pkgs,
	) == 0 {
		return nil, fmt.Errorf(
			"no packages",
		)
	}

	for _, pkg := range pkgs {
		if len(
			pkg.Errors,
		) == 0 {
			continue
		}

		return nil, fmt.Errorf(
			"package %s: %w",
			pkg.ID,
			pkg.Errors[0],
		)
	}

	return pkgs, nil
}
