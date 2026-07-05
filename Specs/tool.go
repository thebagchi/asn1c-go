// Package specs holds ITU-T ASN.1 specification documents and extracted grammar.
//
// Run "go generate ./Specs/" to download specs and extract the grammar.
// Run "go generate -run clean ./Specs/" to remove downloaded artifacts.
// Prerequisites: python3, pip install python-docx, libreoffice

//go:generate python3 extract_grammar.py
//go:generate -run clean python3 extract_grammar.py --clean

package specs
