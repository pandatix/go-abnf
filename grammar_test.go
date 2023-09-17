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

//go:embed testdata/abnf.abnf
var abnfAbnf []byte

//go:embed testdata/fixed-abnf.abnf
var fixedAbnfAbnf []byte

//go:embed testdata/fixed-abnf-raw.abnf
var fixedAbnfRawAbnf []byte

var testsParseAbnf = map[string]struct {
	Input     []byte
	Validate  bool
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
		// This fuzz crasher enabled detecting missing prose-val lexing support.
		Input:     []byte("A=<>\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
}

func Test_U_ParseABNF(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseAbnf {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			assert.NotEmpty(tt.Input)
			_, err := ParseABNF(tt.Input, WithValidation(tt.Validate))

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
		"hex": {
			Str:         "3c",
			Base:        "x",
			ExpectedVal: 0x3c,
		},
		"binary": {
			Str:         "10",
			Base:        "b",
			ExpectedVal: 0b10,
		},
		"decimal": {
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

func Test_U_GetRule(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Rulename   string
		Rulemap    map[string]*rule
		ExpectRule bool
	}{
		"core-rule": {
			Rulename:   "WSP",
			Rulemap:    ABNF.rulemap,
			ExpectRule: true,
		},
		"rulemap-rule": {
			Rulename:   "rulelist",
			Rulemap:    ABNF.rulemap,
			ExpectRule: true,
		},
		"case-insensitive": {
			Rulename:   "wsp",
			Rulemap:    ABNF.rulemap,
			ExpectRule: true,
		},
		"unexisting-rule": {
			Rulename:   "im-n07-4-rul3",
			Rulemap:    ABNF.rulemap,
			ExpectRule: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			rule := getRule(tt.Rulename, tt.Rulemap)

			if tt.ExpectRule {
				assert.NotNil(rule)
			} else {
				assert.Nil(rule)
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
