package goabnf_test

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

var Ggrammar *goabnf.Grammar
var Gerr error

func BenchmarkParseABNF(b *testing.B) {
	var grammar *goabnf.Grammar
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grammar, err = goabnf.ParseABNF(abnfAbnf)
	}
	Ggrammar = grammar
	Gerr = err
}
