package main

import (
	"flag"
	"fmt"
	asn1c "github.com/thebagchi/asn1c-go"
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
	err := asn1c.Parse(*filename)
	if nil != err {
		fmt.Println("Error: ", err)
		os.Exit(0)
	}
}
