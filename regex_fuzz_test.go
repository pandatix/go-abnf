package goabnf_test

import (
	"bytes"
	"regexp"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

func FuzzRegex(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64, rulename string) {
		input, _ := goabnf.ABNF.Generate(seed, "rulelist")
		t.Logf("seed: %d", seed)
		t.Logf("input: %s", bytes.ReplaceAll(input, []byte{'\r', '\n'}, []byte{'\n'}))
		g, err := goabnf.ParseABNF(input)
		if err != nil {
			return
		}

		raw, err := g.Regex(rulename)
		if err != nil {
			if _, ok := err.(*goabnf.ErrRuleNotFound); ok {
				return
			}
			t.Fatalf("was not expecting the regex build to come up with an error, got: %s", err)
			return
		}

		if _, err = regexp.Compile(raw); err != nil {
			t.Fatalf("regex should be compilable, at least for the official Go implementation, got: %s", err)
			return
		}
	})
}
