package asn1c_go

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"regexp"
)

type ModuleDefinition struct {
}

func RemoveBlanks(buffer []byte) []byte {
	regex := regexp.MustCompile("(?m)^\\s*$[\r\n]*")
	return bytes.Trim(regex.ReplaceAll(buffer, []byte("")), "\r\n")
}

func RemoveBlockComment(content []byte) []byte {
	comment := regexp.MustCompile(`/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/`)
	return comment.ReplaceAll(content, []byte(""))
}

func RemoveLineComment(content []byte) []byte {
	comment := regexp.MustCompile(`--.*`)
	return comment.ReplaceAll(content, []byte(""))
}

func RemoveComments(content []byte) []byte {
	return RemoveBlanks(RemoveLineComment(RemoveBlockComment(content)))
}

func Parse(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if nil != err {
		return err
	}
	data = RemoveComments(data)
	fmt.Println(string(data))
	return nil
}
