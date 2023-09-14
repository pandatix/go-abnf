package goabnf

import (
	_ "embed"
	"fmt"
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

//go:embed testdata/abnf.abnf
var abnfAbnf []byte

//go:embed testdata/fixed-abnf.abnf
var fixedAbnfAbnf []byte

//go:embed testdata/fixed-abnf-raw.abnf
var fixedAbnfRawAbnf []byte

func Test_U_ParseABNF(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input     []byte
		ExpectErr bool
	}{
		"void": {
			Input:     voidAbnf,
			ExpectErr: false,
		},
		"atomic": {
			Input:     atomicAbnf,
			ExpectErr: false,
		},
		"platypus": {
			Input:     platypusAbnf,
			ExpectErr: false,
		},
		"fun": {
			Input:     funAbnf,
			ExpectErr: false,
		},
		"noob": {
			Input:     noobAbnf,
			ExpectErr: true, // Due to LF (expected CRLF)
		},
		"rulelist": {
			Input:     rulelistAbnf,
			ExpectErr: false,
		},
		"rule": {
			Input:     ruleAbnf,
			ExpectErr: false,
		},
		"element": {
			Input:     elementAbnf,
			ExpectErr: false,
		},
		"abnf": {
			// This test validates we can parse ABNF using ABNF grammar
			// and the ABNF structural model :)
			Input:     abnfAbnf,
			ExpectErr: false,
		},
		"fixed-abnf": {
			// This test validates we can parse ABNF once fixed by erratum
			// 2968+3076 and RFC 7405 using ABNF grammar and the ABNF
			// structural mode :))
			Input:     fixedAbnfAbnf,
			ExpectErr: false,
		},
		"fixed-abnf-raw": {
			Input:     fixedAbnfRawAbnf,
			ExpectErr: false,
		},
		"Fuzz_9de7f1cac25b4c59": {
			// This fuzz crasher enabled detecting invalid repetition's repeat
			// min/max values extraction.
			Input:     []byte("A=012(\"\")\r\n"),
			ExpectErr: false,
		},
		"Fuzz_9de7f1cac25b4c59 variant 1": {
			Input:     []byte("A=*012(\"\")\r\n"),
			ExpectErr: false,
		},
		"Fuzz_9de7f1cac25b4c59 variant 2": {
			Input:     []byte("A=012*(\"\")\r\n"),
			ExpectErr: false,
		},
		"Fuzz_6c652486622bc04e": {
			// This fuzz crasher enabled detecting bad group's alternation
			// extraction.
			Input:     []byte("A=(  \"\")\r\n"),
			ExpectErr: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			assert.NotEmpty(tt.Input)
			_, err := ParseABNF(tt.Input)

			if tt.ExpectErr {
				assert.NotNil(err)
			} else {
				assert.Nil(err)
			}
		})
	}
}

func Test_U_Atob(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Str         string
		Base        string
		ExpectedVal byte
	}{
		"0x30": {
			Str:         "3c",
			Base:        "x",
			ExpectedVal: 0x3c,
		},
		"0b10": {
			Str:         "10",
			Base:        "b",
			ExpectedVal: 0b10,
		},
		"0d56": {
			Str:         "56",
			Base:        "d",
			ExpectedVal: 56,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			val := atob(tt.Str, tt.Base)

			assert.Equal(tt.ExpectedVal, val)
		})
	}
}

func Test_U_ABNFParseItself(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Test the hardcoded ABNF is:
	// - valid (string method works)
	// - complete (ABNF representation of ABNF can be parsed by ABNF)
	hardcoded := ABNF.ABNF()
	fmt.Printf("hardcoded: %v\n", hardcoded)
	g, err := ParseABNF([]byte(hardcoded))
	if !assert.Nil(err) {
		t.FailNow()
	}

	// 1a
	fresh := g.ABNF()
	fmt.Printf("fresh: %v\n", fresh)
	ng, err := ParseABNF([]byte(fresh))
	assert.Equal(g, ng)
	assert.Nil(err)

	assert.Equal(ABNF, ng)

	// 1b
	sol, err := Parse([]byte(fresh), g, "rulelist")
	assert.NotNil(sol)
	assert.Nil(err)
}
