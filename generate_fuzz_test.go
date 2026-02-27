package goabnf

import (
	"testing"
)

var testsGenerate = map[string]struct {
	Grammar   *Grammar
	Seed      int64
	Rulename  string
	ExpectErr bool
}{
	"self-loop": {
		Grammar:   mustGrammar("a=a\r\n"),
		Seed:      0,
		Rulename:  "a",
		ExpectErr: true,
	},
	"deep-loop": {
		Grammar:   mustGrammar("a=b\r\nb=\"b\" a\r\n"),
		Seed:      0,
		Rulename:  "a",
		ExpectErr: true,
	},
	"avoidable-loop": {
		Grammar:   mustGrammar("a=*a b\r\nb=\"b\" *a\r\n"),
		Seed:      0,
		Rulename:  "a",
		ExpectErr: false,
	},
	"reflected-loop": {
		Grammar:   mustGrammar("a=b\r\nb=b\r\n"),
		Seed:      0,
		Rulename:  "a",
		ExpectErr: true,
	},
	"abnf-rulelist-0": {
		Grammar:   ABNF,
		Seed:      0,
		Rulename:  "rulelist",
		ExpectErr: false,
	},
	"abnf-rulelist-1": {
		Grammar:   ABNF,
		Seed:      1,
		Rulename:  "rulelist",
		ExpectErr: false,
	},
	"abnf-rule-64": {
		Grammar:   ABNF,
		Seed:      64,
		Rulename:  "rule",
		ExpectErr: false,
	},
	"abnf-rule-14": {
		Grammar:   ABNF,
		Seed:      14,
		Rulename:  "rule",
		ExpectErr: false,
	},
	"abnf-rulelist-499": {
		Grammar:   ABNF,
		Seed:      499,
		Rulename:  "rulelist",
		ExpectErr: false,
	},
	"non-ascii": {
		// This test case covers the case where a num-val produces a non-ASCII
		// value, thus has a big value.
		// It comes from #105 and is especially extracted from the TOML official
		// ABNF grammar (https://github.com/toml-lang/toml/blob/1.0.0/toml.abnf)
		// It has slightly be modified to make sure whatever the seed it generates
		// a >1 byte value.
		Grammar:   mustGrammar("non-ascii = %xE000-10FFFF\r\n"),
		Rulename:  "non-ascii",
		ExpectErr: false, // we don't expect an error, just a large byte content
	},
}

func FuzzGeneratedValid(f *testing.F) {
	for _, tt := range testsGenerate {
		f.Add(tt.Seed, tt.Rulename)
	}

	f.Fuzz(func(t *testing.T, seed int64, rulename string) {
		out, err := ABNF.Generate(seed, rulename, WithRepMax(16), WithThreshold(1024))
		if err != nil {
			if len(out) != 0 {
				t.Fatal("output should be empty in case of an error")
			}
			return
		}

		valid, err := ABNF.IsValid(rulename, out)
		if err != nil || !valid {
			t.Fatalf("generated output is invalid, out: %s", out)
		}
	})
}
