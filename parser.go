package asn1c_go

import (
	"bufio"
	"fmt"
	"os"
)

func Parse(filename string) error {
	file, err := os.Open(filename)
	if nil != err {
		return err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	return nil
}
