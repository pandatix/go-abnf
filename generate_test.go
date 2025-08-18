package goabnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testsGenerate = map[string]struct {
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
	}
)

func Test_U_Generate(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsGenerate {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			// Generate a random output for a given rule
			out, err := tt.Grammar.Generate(tt.Seed, tt.Rulename, WithRepMax(4), WithThreshold(64))
			if tt.ExpectErr {
				assert.NotNil(err)
				return
			} else {
				if !assert.Nil(err) {
					return
				}
			}
			assert.NotEmpty(out)
		})
	}
}

func mustGrammar(input string) *Grammar {
	g, err := ParseABNF([]byte(input))
	if err != nil {
		panic(err)
	}
	return g
}
