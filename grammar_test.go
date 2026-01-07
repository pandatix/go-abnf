package goabnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_ParseABNF(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseAbnf {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			assert.NotEmpty(tt.Input)
			g, err := ParseABNF(tt.Input,
				WithValidation(tt.Validate),
				WithRedefineCoreRules(tt.Redefine),
			)
			_ = g

			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected err: %t ; got: %s", tt.ExpectErr, err)
			}
		})
	}
}

func Test_U_ABNFParseItself(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Test the hardcoded ABNF is:
	// - valid (string method works)
	// - complete (ABNF representation of ABNF can be parsed by ABNF)
	hardcoded := ABNF.String()
	g, err := ParseABNF([]byte(hardcoded))
	if !assert.Nil(err) {
		t.FailNow()
	}

	// Test the generated ABNF from the hardcoded ABNF is also:
	// - valid (string method works)
	// - complete (ABNF representation of ABNF can be parsed by ABNF)
	// (1a) with the hardcoded ABNF grammar
	fresh := g.String()
	ng, err := ParseABNF([]byte(fresh))
	assert.Equal(g, ng)
	assert.Nil(err)

	assert.Equal(ABNF, ng)

	// 1b (with the freshly produced ABNF grammar)
	sol, err := Parse([]byte(fresh), g, "rulelist")
	assert.NotNil(sol)
	assert.Nil(err)
}

func Test_U_ParseRootNonGroup(t *testing.T) {
	// Issue #32 use case is a root rule that does not start
	// with a group as its first root alternation element.
	assert := assert.New(t)

	// First we build our grammar
	g, err := ParseABNF(platypusAbnf)
	if !assert.Nil(err) {
		return
	}

	// Then we consider an input, valid according to our grammar.
	input := []byte("a")
	p, err := Parse(input, g, "b")
	if !assert.Nil(err) {
		return
	}

	// Then we make sure there is only 1 possibility, and all
	// subpaths have the proper name.
	if !assert.Len(p, 1) {
		return
	}
	assert.Equal("b", p[0].MatchRule)
	assert.Equal("a", p[0].Subpaths[0].MatchRule)
}

func Test_U_ParseEmptyCharVal(t *testing.T) {
	// Issue #... use case is to parse an empty char-val.
	// In that situation the evaluator would extract a non-empty character
	// leading post-processing operations inadequate.
	assert := assert.New(t)

	{
		g, err := ParseABNF([]byte("a=\"\"\r\n"))
		if !assert.Nil(err) {
			return
		}

		a := g.Rulemap["a"]
		assert.Empty(a.Alternation.Concatenations[0].Repetitions[0].Element.(ElemCharVal).Values)
	}

	{
		g, err := ParseABNF([]byte("a=\"abc\"\r\n"))
		if !assert.Nil(err) {
			return
		}

		a := g.Rulemap["a"]
		bs := a.Alternation.Concatenations[0].Repetitions[0].Element.(ElemCharVal).Values
		assert.Equal("abc", string(bs))
	}
}
