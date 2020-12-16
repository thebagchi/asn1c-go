package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		filename = flag.String("file", "", "Abstract Syntax Notation 1 file")
	)
	flag.Parse()
	if len(*filename) == 0 {
		fmt.Println("Error: ", "input asn1 file required ...")
		os.Exit(0)
	}
}
