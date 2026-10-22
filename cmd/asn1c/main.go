package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thebagchi/asn1c-go/compiler"
)

// main runs the compiler over the files named on the command line.
//
// Revisions:
//   - 2020-12-16 17:44: initial creation
func main() {
	var (
		filename = flag.String(
			"file",
			"",
			"Abstract Syntax Notation 1 file",
		)
	)

	flag.Parse()

	if len(*filename) == 0 {
		fmt.Println(
			"Error: ",
			"input asn1 file required ...",
		)
		os.Exit(0)
	}

	err := compiler.Parse(*filename)
	if err != nil {
		fmt.Println(
			"Error: ",
			err,
		)
		os.Exit(0)
	}
}
