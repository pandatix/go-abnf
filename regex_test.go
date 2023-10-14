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
