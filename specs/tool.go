//go:generate python3 extract_grammar.py

// Package specs holds the ITU-T ASN.1 specification documents and the grammar
// extracted from them.
//
// Run "go generate ./specs/" to download the specifications and extract the
// grammar; it needs python3, python-docx and libreoffice. To remove what that
// downloaded, run the script directly:
//
//	python3 specs/extract_grammar.py --clean
//
// That is not a //go:generate directive because -run is a flag to go generate,
// selecting which directives to run, rather than something a directive can
// carry: written as one it made "go generate ./..." fail with
// exec: "-run": executable file not found.
package specs
