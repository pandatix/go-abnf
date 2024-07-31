package goabnf_test

import (
	"bytes"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

func FuzzRawGrammarToTransitionGraph(f *testing.F) {
	f.Fuzz(func(t *testing.T, input []byte, rulename string) {
		if len(input) > 32 || bytes.Count(input, []byte{'('}) > 2 {
			t.Skip()
		}

		fuzzTarget_GrammarToTransitionGraph(t, input, rulename)
	})
}

func FuzzGeneratedGrammarToTransitionGraph(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64, rulename string) {
		input, _ := goabnf.ABNF.Generate(seed, "rulelist")

		fuzzTarget_GrammarToTransitionGraph(t, input, rulename)
	})
}

func fuzzTarget_GrammarToTransitionGraph(t *testing.T, input []byte, rulename string) {
	g, err := goabnf.ParseABNF(input, goabnf.WithValidation(false))
	if err != nil {
		t.Skip()
	}

	tg, err := g.TransitionGraph(rulename,
		goabnf.WithDeflateRules(true),
		goabnf.WithDeflateNumVals(false),  // don't set to true, else it could easily produce a high number of edges/vertices
		goabnf.WithDeflateCharVals(false), // don't set to true, else it could easily produce a high number of edges/vertices
		goabnf.WithRepetitionThreshold(3),
	)
	if err == nil {
		_ = tg.ToMermaid()
	}
}
