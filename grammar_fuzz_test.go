package goabnf_test

import (
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

func FuzzParseABNF(f *testing.F) {
	for _, test := range testsParseAbnf {
		f.Add(test.Input)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		path, err := goabnf.ParseABNF(input)

		if err != nil {
			if path != nil {
				t.Fatal("Expected no path when error")
			}
		} else {
			if path == nil {
				t.Fatal("Expected a path when no error")
			}
		}
	})
}
