package goabnf

import (
	_ "embed"
	"testing"
)

var Gpath *Path
var Gerr error

func BenchmarkParseABNF(b *testing.B) {
	var path *Path
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path, err = ParseABNF(abnfAbnf)
	}
	Gpath = path
	Gerr = err
}
