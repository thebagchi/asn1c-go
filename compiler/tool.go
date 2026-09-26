//go:generate go tool goyacc -p asn1 -l -o grammar.go grammar.y

// Package compiler holds the goyacc grammar for the ASN.1 module syntax and the
// parser generated from it.
//
// Run "go generate ./compiler/" after editing grammar.y to regenerate
// grammar.go, which is generated and never edited by hand.
//
// -l drops the "//line grammar.y:NNN" directives goyacc writes, which
// otherwise make the Go compiler report an error in a rule action at its
// position in grammar.y rather than in grammar.go. That is worth having and
// is given up for one reason: the directives make every position in the file
// a position in another file, and gci - the import formatter the linters run
// - panics computing a patch against them once the file has an import block
// to rearrange, which it does now that the AST is a schema. A run that
// cannot start is not a gate that passed.
//
// To get the mapping back while debugging an action, regenerate by hand
// without -l. Nothing else depends on it.
package compiler
