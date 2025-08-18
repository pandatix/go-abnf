package goabnf

import (
	"bytes"
	"regexp"
	"testing"
)

var testsRegex = map[string]struct {
	Grammar   *Grammar
	Rulename  string
	ExpectErr bool
}{
	"abnf-alpha": {
		Grammar:   ABNF,
		Rulename:  "alpha",
		ExpectErr: false,
	},
	"cycle": {
		Grammar:   mustGrammar(string(cycleAbnf)),
		Rulename:  "a",
		ExpectErr: true,
	},
	"void": {
		Grammar:   mustGrammar(string(voidAbnf)),
		Rulename:  "",
		ExpectErr: true,
	},
	"nocycle": {
		Grammar:   mustGrammar(string(nocycleAbnf)),
		Rulename:  "a",
		ExpectErr: false,
	},
	"group-option": {
		Grammar:   mustGrammar("a = 1*(*[\"b.\"] *3%x61.7a)\r\n"),
		Rulename:  "a",
		ExpectErr: false,
	},
}

func FuzzRegex(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64, rulename string) {
		input, _ := ABNF.Generate(seed, "rulelist")
		t.Logf("seed: %d", seed)
		t.Logf("input: %s", bytes.ReplaceAll(input, []byte{'\r', '\n'}, []byte{'\n'}))
		g, err := ParseABNF(input)
		if err != nil {
			return
		}

		raw, err := g.Regex(rulename)
		if err != nil {
			if _, ok := err.(*ErrRuleNotFound); ok {
				return
			}
			if err == ErrHandlingProseVal {
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
