package goabnf

import (
	_ "embed"
	"testing"
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
		// This fuzz crasher enabled detecting missing prose-val lexing support.
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
		Input:     []byte("a = %b00000000-11111111\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"binary-out": {
		Input:     []byte("a = %b0000000000000-111111110\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"decimal-maximal": {
		Input:     []byte("a = %d000-255\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"decimal-out": {
		Input:     []byte("a = %d000000-256\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"hexadecimal-maximal": {
		Input:     []byte("a = %x00-0FF\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"hexadecimal-out": {
		Input:     []byte("a = %x000-FF0\r\n"),
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
}

func FuzzParseABNF(f *testing.F) {
	for _, test := range testsParseAbnf {
		f.Add(test.Input)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		grammar, err := ParseABNF(input)

		if err != nil {
			if grammar != nil {
				t.Fatal("Expected no path when error")
			}
			if err, ok := err.(*ErrMultipleSolutionsFound); ok {
				t.Fatalf("For input %s, got error %s", input, err)
			}
			return
		}
		if grammar == nil {
			t.Fatal("Expected a grammar when no error")
		}
	})
}

func FuzzParseABNF_Generate(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		input, _ := ABNF.Generate(seed, "rulelist")

		g, err := ParseABNF(input, WithValidation(false))

		if err != nil {
			if g != nil {
				t.Fatal("Expected no path when error")
			}
			if err, ok := err.(*ErrMultipleSolutionsFound); ok {
				t.Fatalf("For input %s, got error %s", input, err)
			}
			return
		}
		if g == nil {
			t.Fatal("Expected a grammar when no error")
			return
		}
	})
}
