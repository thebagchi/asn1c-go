package common

import (
	"fmt"

	"golang.org/x/tools/go/packages"
)

// LoadTyped reads the named packages from dir, with syntax and type information.
// It reads their tests.
// A package with an error is refused, because a call graph from a partial type check lies.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func LoadTyped(
	dir string,
	patterns []string,
) ([]*packages.Package, error) {
	var (
		cfg = &packages.Config{
			Mode: packages.NeedName |
				packages.NeedFiles |
				packages.NeedSyntax |
				packages.NeedTypes |
				packages.NeedTypesInfo |
				packages.NeedModule,
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
