package goabnf_test

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/nocycle.abnf
var nocycleAbnf []byte

//go:embed testdata/cycle.abnf
var cycleAbnf []byte

func Test_U_IsDAG(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input         []byte
		ExpectedIsDag bool
	}{
		"no-cycle": {
			Input:         nocycleAbnf,
			ExpectedIsDag: true,
		},
		"cycle": {
			Input:         cycleAbnf,
			ExpectedIsDag: false,
		},
		"abnf": {
			// The ABNF grammar is cylic due to the ~Composite DP on alternation with group and option
			Input:         abnfAbnf,
			ExpectedIsDag: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := goabnf.ParseABNF(tt.Input)
			if !assert.Nil(err) {
				t.FailNow()
			}
			// Side checks that this dependency graph does not produce an
			// empty dependency graph. It should not be, at any time,
			// as only the diagram header is a non-empty content.
			mrmd := g.DependencyGraph().Mermaid()
			assert.NotEmpty(mrmd)
			// Do the same with the pretty print.
			ptp := g.PrettyPrint()
			assert.NotEmpty(ptp)

			isDag := g.IsDAG()
			assert.Equal(tt.ExpectedIsDag, isDag)
		})
	}
}

func Test_U_RuleContainsCycle(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Grammar     *goabnf.Grammar
		Rulename    string
		ExpectedRes bool
		ExpectErr   bool
	}{
		"abnf": {
			Grammar:     goabnf.ABNF,
			Rulename:    "rulelist",
			ExpectedRes: true,
			ExpectErr:   false,
		},
		"a-self-left": {
			Grammar:     mustGrammar("a = a \"a\"\r\n"),
			Rulename:    "a",
			ExpectedRes: true,
			ExpectErr:   false,
		},
		"a-self-right": {
			Grammar:     mustGrammar("a = \"a\" a\r\n"),
			Rulename:    "a",
			ExpectedRes: true,
			ExpectErr:   false,
		},
		"ab": {
			Grammar:     mustGrammar("a = b \"a\"\r\nb = a \"b\"\r\n"),
			Rulename:    "a",
			ExpectedRes: true,
			ExpectErr:   false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			res, err := tt.Grammar.RuleContainsCycle(tt.Rulename)
			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected error: %t ; got %v", tt.ExpectErr, err)
			}
			assert.Equal(tt.ExpectedRes, res)
		})
	}
}

func Test_U_IsLeftTerminating(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Grammar     *goabnf.Grammar
		Rulename    string
		ExpectedRes bool
		ExpectErr   bool
	}{
		"abnf": {
			Grammar:     goabnf.ABNF,
			Rulename:    "rulelist",
			ExpectedRes: true,
			ExpectErr:   false,
		},
		"a-left": {
			Grammar:     mustGrammar("a = a \"a\"\r\n"),
			Rulename:    "a",
			ExpectedRes: false,
			ExpectErr:   false,
		},
		"a-right": {
			Grammar:     mustGrammar("a = \"a\" a\r\n"),
			Rulename:    "a",
			ExpectedRes: true,
			ExpectErr:   false,
		},
		"ab-left": {
			Grammar:     mustGrammar("a = b \"a\"\r\nb = a \"b\"\r\n"),
			Rulename:    "a",
			ExpectedRes: false,
			ExpectErr:   false,
		},
		"ab-right": {
			Grammar:     mustGrammar("a = b \"a\"\r\nb = \"b\"\r\n"),
			Rulename:    "a",
			ExpectedRes: true,
			ExpectErr:   false,
		},
		"option-a-left": {
			Grammar:     mustGrammar("a = [a] \"a\"\r\n"),
			Rulename:    "a",
			ExpectedRes: false,
			ExpectErr:   false,
		},
		"option-a-right": {
			Grammar:     mustGrammar("a = [\"a\"] a\r\n"),
			Rulename:    "a",
			ExpectedRes: false,
			ExpectErr:   false,
		},
		"group-a-left": {
			Grammar:     mustGrammar("a = (a) \"a\"\r\n"),
			Rulename:    "a",
			ExpectedRes: false,
			ExpectErr:   false,
		},
		"group-a-right": {
			Grammar:     mustGrammar("a = (\"a\") a\r\n"),
			Rulename:    "a",
			ExpectedRes: true,
			ExpectErr:   false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			res, err := tt.Grammar.IsLeftTerminating(tt.Rulename)
			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected error: %t ; got %v", tt.ExpectErr, err)
			}
			assert.Equal(tt.ExpectedRes, res)
		})
	}
}
