package main

import (
	"go/ast"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

// BANNER reports a generated file whose banner is not the first line.
var (
	BANNER = _New(
		"banner",
		"banner reports a generated file whose banner is not the first line",
		_RunBanner,
	)
)

// _RunBanner reports each generated .go file whose banner is not line 1.
// The go command writes a test harness into the build cache.
// That file is not a .go file of this module, so this check skips it.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//   - 2026-10-04 00:19: skip a generated file whose name does not end in .go
//   - 2026-10-04 01:38: report an error line with the rule and the fix
func _RunBanner(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		report, err := _BannerFile(
			pass,
			file,
		)
		if err != nil {
			return nil, err
		}

		if !report {
			continue
		}

		_Fail(
			pass,
			file.Pos(),
			BAD_BANNER,
			FIX_BANNER,
		)
	}

	return nil, nil
}

// _BannerFile reports whether one generated file breaks the banner rule.
// A file whose name does not end in .go is the go test harness, and it is clean.
//
// Revisions:
//   - 2026-10-04 11:12: initial creation
func _BannerFile(
	pass *analysis.Pass,
	file *ast.File,
) (bool, error) {
	if common.Written(
		file,
	) {
		return false, nil
	}

	name := pass.Fset.File(
		file.Pos(),
	).Name()
	if !strings.HasSuffix(
		name,
		".go",
	) {
		return false, nil
	}

	line, err := _FirstLine(
		pass,
		file,
	)
	if err != nil {
		return false, err
	}

	return !BANNER_FORM.MatchString(
		line,
	), nil
}

// _FirstLine returns the first line of the file that holds the syntax tree.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _FirstLine(
	pass *analysis.Pass,
	file *ast.File,
) (string, error) {
	var (
		name = pass.Fset.File(
			file.Pos(),
		).Name()
		data, err = os.ReadFile(
			name,
		)
	)
	if err != nil {
		return "", err
	}

	line, _, _ := strings.Cut(
		string(data),
		"\n",
	)

	return line, nil
}
