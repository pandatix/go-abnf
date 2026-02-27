package goabnf

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed testdata/void.abnf
var voidAbnf []byte

//go:embed testdata/atomic.abnf
var atomicAbnf []byte

//go:embed testdata/platypus.abnf
var platypusAbnf []byte

//go:embed testdata/fun.abnf
var funAbnf []byte

//go:embed testdata/noob.abnf
var noobAbnf []byte

//go:embed testdata/rulelist.abnf
var rulelistAbnf []byte

//go:embed testdata/rule.abnf
var ruleAbnf []byte

//go:embed testdata/element.abnf
var elementAbnf []byte

//go:embed testdata/multi.abnf
var multiAbnf []byte

//go:embed testdata/abnf.abnf
var abnfAbnf []byte

//go:embed testdata/fixed-abnf.abnf
var fixedAbnfAbnf []byte

//go:embed testdata/fixed-abnf-raw.abnf
var fixedAbnfRawAbnf []byte

//go:embed testdata/aftn.abnf
var aftnAbnf []byte

//go:embed testdata/fuzz_regex_eaa469604868c87f.abnf
var fuzzRegex_eaa469604868c87fAbnf []byte

//go:embed testdata/redefine.abnf
var redefineAbnf []byte

//go:embed testdata/toml.abnf
var tomlAbnf []byte

var testsParseAbnf = map[string]struct {
	Input     []byte
	Validate  bool
	Redefine  bool
	ExpectErr bool
}{
	"void": {
		Input:     voidAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"atomic": {
		Input:     atomicAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"platypus": {
		Input:     platypusAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"fun": {
		Input:     funAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"noob": {
		Input:     noobAbnf,
		Validate:  false,
		ExpectErr: true, // Due to LF (expected CRLF)
	},
	"rulelist": {
		Input:     rulelistAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"rule": {
		Input:     ruleAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"element": {
		Input:     elementAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"multi": {
		Input:     multiAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"abnf": {
		// This test validates we can parse ABNF using ABNF grammar
		// and the ABNF structural model :)
		Input:     abnfAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"fixed-abnf": {
		// This test validates we can parse ABNF once fixed by erratum
		// 2968+3076 and RFC 7405 using ABNF grammar and the ABNF
		// structural mode :))
		Input:     fixedAbnfAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"fixed-abnf-raw": {
		Input:     fixedAbnfRawAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"aftn": {
		Input:     aftnAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_9de7f1cac25b4c59": {
		// This fuzz crasher enabled detecting invalid repetition's repeat
		// min/max values extraction.
		Input:     []byte("A=012(\"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_9de7f1cac25b4c59 variant 1": {
		Input:     []byte("A=*012(\"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_9de7f1cac25b4c59 variant 2": {
		Input:     []byte("A=012*(\"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_6c652486622bc04e": {
		// This fuzz crasher enabled detecting bad group's alternation
		// extraction.
		Input:     []byte("A=(  \"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_395eb15ada9c6900": {
		// This fuzz crasher enabled detecting missing prose-val evaluation support.
		Input:     []byte("A=<>\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_eaa469604868c87f": {
		// This fuzz crasher enabled detecting a mis-undhandling of the defined-as character.
		Input:     fuzzRegex_eaa469604868c87fAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"binary-maximal": {
		Input:     []byte("a = %b0-100001111111111111111\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"binary-out": {
		Input:     []byte("a = %b0-100010000000000000000\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"decimal-maximal": {
		Input:     []byte("a = %d0-1114111\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"decimal-out": {
		Input:     []byte("a = %d0-1114112\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"hexadecimal-maximal": {
		Input:     []byte("a = %x0-10FFFF\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"hexadecimal-out": {
		Input:     []byte("a = %x0-110000\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"redefine": {
		// This tests for behavioral retrocompatiblity
		Input:     redefineAbnf,
		Redefine:  false, // default behavior
		ExpectErr: true,
	},
	"redefine-granted": {
		Input:     redefineAbnf,
		Redefine:  true,
		ExpectErr: false,
	},
	"toml": {
		// Issue #105 shows the implementation did not cover large enough values.
		// num-values were generated over a single byte, which made it impossible
		// to handle unicode characters, e.g., emojis.
		Input:     tomlAbnf,
		Redefine:  true, // at the end ABNF core rules are reproduced
		Validate:  true, // should be valid
		ExpectErr: false,
	},
}

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
