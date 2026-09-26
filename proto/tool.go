//go:generate go tool buf generate

// Package proto holds ast.proto, the schema the AST is declared in, and the
// buf configuration that turns it into ast/ast.pb.go.
//
// The package has no Go in it beyond this file. It exists so that
// "go generate ./proto/" has somewhere to hang the directive, the way
// compiler/tool.go does for goyacc. buf and protoc-gen-go are pinned as tool
// directives in go.mod, so neither is imported by anything this module builds
// and a checkout needs no protoc.
//
// Run "go generate ./proto/" after editing ast.proto. Nothing regenerates it
// on its own, and ast/ast.pb.go is generated and never edited by hand.
package proto
