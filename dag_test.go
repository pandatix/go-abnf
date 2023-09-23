package goabnf_test

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/nocycle.abnf
var nocycleAbnf []byte

//go:embed testdata/cycle.abnf
var cycleAbnf []byte

func Test_U_IsDAG(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input         []byte
		ExpectedIsDag bool
	}{
		"no-cycle": {
			Input:         nocycleAbnf,
			ExpectedIsDag: true,
		},
		"cycle": {
			Input:         cycleAbnf,
			ExpectedIsDag: false,
		},
		"abnf": {
			// The ABNF grammar is cylic due to the ~Composite DP on alternation with group and option
			Input:         abnfAbnf,
			ExpectedIsDag: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := goabnf.ParseABNF(tt.Input)
			if !assert.Nil(err) {
				t.FailNow()
			}

			isDag := g.IsDAG()
			assert.Equal(tt.ExpectedIsDag, isDag)
		})
	}
}
