package goabnf_test

import (
	"regexp"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/stretchr/testify/assert"
)

var testsRegex = map[string]struct {
	Grammar   *goabnf.Grammar
	Rulename  string
	ExpectErr bool
}{
	"abnf-alpha": {
		Grammar:   goabnf.ABNF,
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

func Test_U_Regex(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsRegex {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			reg, err := tt.Grammar.Regex(tt.Rulename)
			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected err: %t ; got %s", tt.ExpectErr, err)
				return
			}

			// Check can compile to Go regex
			_, err = regexp.Compile(reg)
			assert.Nil(err)
		})
	}
}
