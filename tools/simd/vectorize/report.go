//go:build ignore

// Command report classifies every loop under the paths given and prints what it found.
//
// It changes nothing. The point is to say which loops could be rewritten as vector kernels
// and, for the rest, which statement is in the way - so a person deciding where to spend
// effort on a hand-written kernel has the list in front of them.
//
// Usage:
//
//	go run tools/simd/vectorize/report.go ./lib/...
//	go run tools/simd/vectorize/report.go lib/bitbuffer lib/per
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thebagchi/asn1c-go/tools/simd/vectorize"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("vectorize: ")

	if len(os.Args) < 2 {
		log.Fatal("usage: report <dir>...")
	}

	var (
		set   = token.NewFileSet()
		safe  []*vectorize.Verdict
		block = map[string]int{}
		total int
	)

	for _, root := range os.Args[1:] {
		files, err := _Files(strings.TrimSuffix(root, "/..."))
		if err != nil {
			log.Fatal(err)
		}

		for _, path := range files {
			file, err := parser.ParseFile(set, path, nil, 0)
			if err != nil {
				log.Fatalf("parse %s: %v", path, err)
			}

			for _, found := range vectorize.Analyze(set, file) {
				total++

				if found.Safe() {
					safe = append(safe, found)

					continue
				}

				block[_Bucket(found.Reason())]++
			}
		}
	}

	_Print(safe, block, total)
}

// _Files lists the non-test Go files under a directory tree.
func _Files(root string) ([]string, error) {
	var (
		found []string
	)

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir():
			return nil
		case !strings.HasSuffix(path, ".go"):
			return nil
		case strings.HasSuffix(path, "_test.go"):
			return nil
		}

		found = append(found, path)

		return nil
	})

	return found, err
}

// _Bucket shortens a reason so the summary groups rather than lists.
func _Bucket(reason string) string {
	if cut, _, found := strings.Cut(reason, ","); found {
		return cut
	}

	if len(reason) > 64 {
		return reason[:64] + "..."
	}

	return reason
}

// _Print writes the report.
func _Print(safe []*vectorize.Verdict, block map[string]int, total int) {
	fmt.Printf("%d loops examined\n\n", total)

	fmt.Printf("vectorisable: %d\n", len(safe))

	for _, found := range safe {
		fmt.Printf(
			"  %s\n      writes %s, reads %v, stencil %v\n",
			found.Position(), found.Store(), found.Loads(), found.Stencil(),
		)
	}

	fmt.Printf("\nrefused: %d\n", total-len(safe))

	var (
		reasons = make([]string, 0, len(block))
	)

	for reason := range block {
		reasons = append(reasons, reason)
	}

	sort.Slice(reasons, func(i, j int) bool {
		return block[reasons[i]] > block[reasons[j]]
	})

	for _, reason := range reasons {
		fmt.Printf("  %3d  %s\n", block[reason], reason)
	}
}
