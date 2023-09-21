package goabnf_test

import (
	"testing"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/stretchr/testify/assert"
)

var (
	testsGenerate = map[string]struct {
		Grammar  *goabnf.Grammar
		Seed     int64
		Rulename string
	}{
		"abnf-rulelist-0": {
			Grammar:  goabnf.ABNF,
			Seed:     0,
			Rulename: "rulelist",
		},
		"abnf-rulelist-1": {
			Grammar:  goabnf.ABNF,
			Seed:     1,
			Rulename: "rulelist",
		},
		"abnf-rule-64": {
			Grammar:  goabnf.ABNF,
			Seed:     64,
			Rulename: "rule",
		},
		"abnf-rule-14": {
			Grammar:  goabnf.ABNF,
			Seed:     14,
			Rulename: "rule",
		},
		"abnf-rulelist-499": {
			Grammar:  goabnf.ABNF,
			Seed:     499,
			Rulename: "rulelist",
		},
	}
)

func Test_U_Generate(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsGenerate {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			// Generate a random output for a given rule
			out, err := tt.Grammar.Generate(tt.Seed, tt.Rulename, goabnf.WithRepMax(4), goabnf.WithThreshold(64))
			assert.Nil(err)
			assert.NotEmpty(out)

			// Verify it is valid
			valid := tt.Grammar.IsValid(tt.Rulename, out)
			assert.Truef(valid, "generated output should be valid: %s", out)
		})
	}
}
