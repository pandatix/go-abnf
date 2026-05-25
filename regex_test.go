package goabnf

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testsRegex = map[string]struct {
	Grammar   *Grammar
	Rulename  string
	ExpectErr bool
}{
	"abnf-alpha": {
		Grammar:   ABNF,
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
	// Bounded variable repetition (min > 0, max < inf, min != max):
	// the earlier switch was missing this case and silently emitted
	// the element with no quantifier. Now must emit "{min,max}".
	"variable-bounded-repetition": {
		Grammar:   mustGrammar("phone = \"+\" 4*15DIGIT\r\n"),
		Rulename:  "phone",
		ExpectErr: false,
	},
}

// Test_U_Regex_VariableBoundedQuantifier locks in the m*n
// quantifier output ({min,max}) and verifies the result matches a
// well-formed input and rejects out-of-range inputs.
func Test_U_Regex_VariableBoundedQuantifier(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	g := mustGrammar("phone = \"+\" 4*15DIGIT\r\n")
	reg, err := g.Regex("phone")
	assert.NoError(err)

	// Output must carry {4,15} for the digit repetition; without
	// the fix the bound was silently dropped.
	assert.Contains(reg, "{4,15}", "expected {4,15} quantifier in regex output")

	compiled, err := regexp.Compile("^" + reg + "$")
	assert.NoError(err)
	assert.True(compiled.MatchString("+1234"))
	assert.True(compiled.MatchString("+123456789012345"))
	assert.False(compiled.MatchString("+123"))
	assert.False(compiled.MatchString("+1234567890123456"))
}

// Test_U_Regex_FromZeroBoundedQuantifier checks that *mRULE
// emits {0,m} rather than {,m}; Go's regexp (RE2) does not
// accept the leading-comma form.
func Test_U_Regex_FromZeroBoundedQuantifier(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	g := mustGrammar("opt = *3DIGIT\r\n")
	reg, err := g.Regex("opt")
	assert.NoError(err)

	assert.Contains(reg, "{0,3}", "expected {0,3} (not {,3}) for RE2 compatibility")
	assert.NotContains(reg, "{,", "regex must not contain RE2-incompatible {,N} form")
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
