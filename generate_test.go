package goabnf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_U_Generate(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsGenerate {
		t.Run(testname, func(t *testing.T) {
			// Generate a random output for a given rule
			out, err := tt.Grammar.Generate(tt.Seed, tt.Rulename, WithRepMax(4), WithThreshold(64))
			if tt.ExpectErr {
				require.Error(t, err)
				return
			}

			require.NotEmpty(t, out)
			require.NoError(t, err)
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
