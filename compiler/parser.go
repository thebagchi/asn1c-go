package compiler

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

// ModuleDefinition is the AST node for a module definition. It is empty while
// the grammar that fills it is being written.
type ModuleDefinition struct {
	// Empty
}

// RemoveBlanks drops blank lines from buffer.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func RemoveBlanks(buffer []byte) []byte {
	regex := regexp.MustCompile("(?m)^\\s*$[\r\n]*")
	return bytes.Trim(regex.ReplaceAll(buffer, []byte("")), "\r\n")
}

// RemoveBlockComment drops every /* ... */ comment from content, including
// one written inside another.
//
// X.680 12.6.4 nests them: a comment opened inside a comment must be closed
// before the outer one is, so "/* a /* b */ c */" is one comment and not two
// with "c */" left between them. No regular expression counts, so the content
// is walked and _Block measures each comment - the same one the lexer uses,
// because two answers to where a comment ends is one too many.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-09-26 09:14: comments nest, so the depth is counted
func RemoveBlockComment(content []byte) []byte {
	kept := make([]byte, 0, len(content))

	for index := 0; index < len(content); {
		length := _Block(content[index:])
		if length == 0 {
			kept = append(kept, content[index])
			index++

			continue
		}

		index += length
	}

	return kept
}

// RemoveLineComment drops every -- comment from content.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func RemoveLineComment(content []byte) []byte {
	comment := regexp.MustCompile(`--.*`)
	return comment.ReplaceAll(content, []byte(""))
}

// RemoveComments drops both comment forms from content.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func RemoveComments(content []byte) []byte {
	return RemoveBlanks(RemoveLineComment(RemoveBlockComment(content)))
}

// Parse reads the ASN.1 source at filename and reports what it could not
// parse.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func Parse(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	data = RemoveComments(data)
	fmt.Println(string(data))

	return nil
}
