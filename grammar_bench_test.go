package goabnf

import (
	_ "embed"
	"testing"
)

var Ggrammar *Grammar
var Gerr error

func BenchmarkParseABNF(b *testing.B) {
	var grammar *Grammar
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grammar, err = ParseABNF(abnfAbnf)
	}
	Ggrammar = grammar
	Gerr = err
}
