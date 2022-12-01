package goabnf_test

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/stretchr/testify/assert"
)

//go:embed samples/RFC5234-errata2968-errata3076.abnf
var sample_rfc5234 string

//go:embed samples/NIST-IR_7695_Figure5-1.abnf
var sample_nistir7695_figure51 string

//go:embed samples/NIST-IR_7695_Figure6-1.abnf
var sample_nistir7695_figure61 string

//go:embed samples/NIST-IR_7695_Figure6-2.abnf
var sample_nistir7695_figure62 string

//go:embed samples/NIST-IR_7695_Figure6-3.abnf
var sample_nistir7695_figure63 string

func TestParseABNF(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input           []byte
		ExpectedGrammar *goabnf.Grammar
		ExpectedErr     error
	}{
		"RFC 5234":                {},
		"NIST-IR 7695 Figure 5-1": {},
		"NIST-IR 7695 Figure 6-1": {},
		"NIST-IR 7695 Figure 6-2": {},
		"NIST-IR 7695 Figure 6-3": {},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			grammar, err := goabnf.ParseABNF(tt.Input)

			assert.Equal(tt.ExpectedGrammar, grammar)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
