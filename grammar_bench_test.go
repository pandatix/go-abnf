package goabnf

import (
	_ "embed"
	"strconv"
	"strings"
	"testing"
)

var Ggrammar *Grammar
var Gerr error

func BenchmarkParseABNF(b *testing.B) {
	var grammar *Grammar
	var err error

	for b.Loop() {
		grammar, err = ParseABNF(abnfAbnf)
	}
	Ggrammar = grammar
	Gerr = err
}

var Gforest *Forest

func BenchmarkParseForest_LongRepetition(b *testing.B) {
	g := mustGrammar("line = word %x20 number %x0A\r\nword = 1*ALPHA\r\nnumber = 1*DIGIT\r\n")
	var err error
	for _, n := range []int{1024, 4096, 16384} {
		input := []byte(strings.Repeat("a", n) + " 1\n")
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			var f *Forest
			for b.Loop() {
				f, err = ParseForest(input, g, "line")
			}
			Gforest = f
			Gerr = err
		})
	}
}
