package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

// _Edges returns one line for each call the question selects.
// A changed run with no Go file in the diff returns no lines.
// The definition set and the call set come from one type check, so the objects match.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Edges(opt *_Opt) ([]string, error) {
	patterns, keep, err := _Scope(
		opt,
	)
	if err != nil {
		return nil, err
	}

	if patterns == nil {
		return nil, nil
	}

	pkgs, err := common.LoadTyped(
		opt.dir,
		patterns,
	)
	if err != nil {
		return nil, err
	}

	return _Lines(
		opt,
		pkgs,
		_Marked(
			opt,
			pkgs,
			keep,
		),
	), nil
}

// _Scope returns the package paths and the changed-file set.
// A nil path list means a changed run found no Go file.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Scope(opt *_Opt) ([]string, map[string]bool, error) {
	if !opt.changed {
		return opt.patterns, nil, nil
	}

	files, err := common.ChangedGo(
		opt.dir,
	)
	if err != nil {
		return nil, nil, err
	}

	if len(
		files,
	) == 0 {
		return nil, nil, nil
	}

	keep, err := _Abs(
		opt.dir,
		files,
	)
	if err != nil {
		return nil, nil, err
	}

	return _Patterns(
		files,
	), keep, nil
}

// _Marked returns the functions defined in the diff.
// A name query returns nil, and the name match does not use the set.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Marked(
	opt *_Opt,
	pkgs []*packages.Package,
	keep map[string]bool,
) map[types.Object]bool {
	if !opt.changed {
		return nil
	}

	defs := map[types.Object]bool{}

	for _, pkg := range pkgs {
		_Define(
			defs,
			keep,
			pkg,
		)
	}

	return defs
}

// _Define records each function declared in a changed file.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Define(
	defs map[types.Object]bool,
	keep map[string]bool,
	pkg *packages.Package,
) {
	if pkg.TypesInfo == nil {
		return
	}

	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}

			at := pkg.Fset.Position(
				fn.Pos(),
			)
			if !keep[filepath.Clean(
				at.Filename,
			)] {
				continue
			}

			obj := pkg.TypesInfo.Defs[fn.Name]
			if obj == nil {
				continue
			}

			defs[obj] = true
		}
	}
}

// _Lines formats each selected call.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Lines(
	opt *_Opt,
	pkgs []*packages.Package,
	defs map[types.Object]bool,
) []string {
	var lines []string

	for _, pkg := range pkgs {
		lines = _Package(
			lines,
			&_Scan{
				opt:  opt,
				pkg:  pkg,
				defs: defs,
			},
		)
	}

	slices.Sort(
		lines,
	)

	return lines
}

// _Scan carries the question and the package under the walk.
type _Scan struct {
	opt  *_Opt
	pkg  *packages.Package
	defs map[types.Object]bool
	root string
}

// _Package appends the calls of one package.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Package(
	lines []string,
	scan *_Scan,
) []string {
	if scan.pkg.TypesInfo == nil {
		return lines
	}

	root, err := filepath.Abs(
		scan.opt.dir,
	)
	if err != nil {
		root = scan.opt.dir
	}

	scan.root = root

	for _, file := range scan.pkg.Syntax {
		lines = _File(
			lines,
			scan,
			file,
		)
	}

	return lines
}

// _File appends the calls inside each function of one file.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _File(
	lines []string,
	scan *_Scan,
	file *ast.File,
) []string {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}

		var (
			obj    = scan.pkg.TypesInfo.Defs[fn.Name]
			caller = _Func(
				obj,
			)
		)
		if caller == nil {
			continue
		}

		lines = _Body(
			lines,
			scan,
			caller,
			fn.Body,
		)
	}

	return lines
}

// _Body appends each call in one function body.
// A function literal keeps the enclosing function as the caller.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Body(
	lines []string,
	scan *_Scan,
	caller *types.Func,
	body *ast.BlockStmt,
) []string {
	ast.Inspect(
		body,
		func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			lines = _Add(
				lines,
				scan,
				caller,
				call,
			)

			return true
		},
	)

	return lines
}

// _Add appends the call when the callee is the one the question names.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Add(
	lines []string,
	scan *_Scan,
	caller *types.Func,
	call *ast.CallExpr,
) []string {
	callee := _Callee(
		scan.pkg.TypesInfo,
		call,
	)
	if !_Want(
		scan.opt,
		scan.defs,
		callee,
	) {
		return lines
	}

	at := scan.pkg.Fset.Position(
		call.Pos(),
	)
	if !at.IsValid() {
		return lines
	}

	return append(
		lines,
		fmt.Sprintf(
			"%s:%d: %s calls %s",
			_Rel(
				scan.root,
				at.Filename,
			),
			at.Line,
			caller.FullName(),
			callee.FullName(),
		),
	)
}

// _Callee returns the function a call expression names.
// A conversion or a built-in is not a function call for this graph.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Callee(
	info *types.Info,
	call *ast.CallExpr,
) *types.Func {
	switch fun := ast.Unparen(
		call.Fun,
	).(type) {
	case *ast.Ident:
		return _Func(
			info.Uses[fun],
		)
	case *ast.SelectorExpr:
		fn := _Func(
			info.Uses[fun.Sel],
		)
		if fn != nil {
			return fn
		}

		sel := info.Selections[fun]
		if sel == nil {
			return nil
		}

		return _Func(
			sel.Obj(),
		)
	default:
		return nil
	}
}

// _Func returns obj when it is a function.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Func(obj types.Object) *types.Func {
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}

	return fn
}

// _Want reports whether callee belongs in the answer.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Want(
	opt *_Opt,
	defs map[types.Object]bool,
	callee *types.Func,
) bool {
	if callee == nil {
		return false
	}

	if opt.changed {
		return defs[callee]
	}

	if callee.Name() != opt.name {
		return false
	}

	if opt.pkg == "" {
		return true
	}

	if callee.Pkg() == nil {
		return false
	}

	return callee.Pkg().Path() == opt.pkg || callee.Pkg().Name() == opt.pkg
}

// _Rel returns path relative to root when path is inside root.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Rel(
	root string,
	path string,
) string {
	rel, err := filepath.Rel(
		root,
		path,
	)
	if err != nil || strings.HasPrefix(
		rel,
		"..",
	) {
		return filepath.ToSlash(
			path,
		)
	}

	return filepath.ToSlash(
		rel,
	)
}

// _Patterns returns one package path for each directory that holds a changed file.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Patterns(files []string) []string {
	seen := map[string]bool{}

	var patterns []string

	for _, file := range files {
		var (
			dir = filepath.ToSlash(
				filepath.Dir(
					file,
				),
			)
			pattern = "."
		)
		if dir != "." {
			pattern = "./" + dir
		}

		if seen[pattern] {
			continue
		}

		seen[pattern] = true
		patterns = append(
			patterns,
			pattern,
		)
	}

	return patterns
}

// _Abs returns the absolute path of each changed file.
//
// Revisions:
//   - 2026-10-21 21:16: initial creation
func _Abs(
	dir string,
	files []string,
) (map[string]bool, error) {
	root, err := filepath.Abs(
		dir,
	)
	if err != nil {
		return nil, err
	}

	set := map[string]bool{}

	for _, file := range files {
		path := filepath.Join(
			root,
			filepath.FromSlash(
				file,
			),
		)
		set[filepath.Clean(
			path,
		)] = true
	}

	return set, nil
}
