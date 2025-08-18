package goabnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_Generate(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsGenerate {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			// Generate a random output for a given rule
			out, err := tt.Grammar.Generate(tt.Seed, tt.Rulename, WithRepMax(4), WithThreshold(64))
			if tt.ExpectErr {
				assert.NotNil(err)
				return
			} else {
				if !assert.Nil(err) {
					return
				}
			}
			assert.NotEmpty(out)
		})
	}
}

func mustGrammar(input string) *Grammar {
	g, err := ParseABNF([]byte(input))
	if err != nil {
		panic(err)
	}
	return g
}
