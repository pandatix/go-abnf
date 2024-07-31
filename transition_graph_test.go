package goabnf

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_RepGraphIO(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input               string
		ExpectedEntrypoints int
		ExpectedEndpoints   int
	}{
		"0-1": {
			Input:               "a = 0*1b",
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   2,
		},
		"0-n'": {
			Input:               "a = 0*2b",
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   3,
		},
		"0-inf": {
			Input:               "a = 0*b",
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   2,
		},
		"n=1-1": {
			Input:               "a = 1*1b",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"n=1-n'": {
			Input:               "a = 1*3b",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   3,
		},
		"n>1-n'": {
			Input:               "a = 2*3b",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   2,
		},
		"n=1-inf": {
			Input:               "a = 1*b",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"n>1-inf": {
			Input:               "a = 2*b",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"n=n'>1": {
			Input:               "a = 3b",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"simplify": {
			// The input is an isomorphism of "a = *c"
			Input:               "a = *(0*1c)",
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   2,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := ParseABNF([]byte(tt.Input+"\r\n"), WithValidation(false))
			if !assert.Nil(err) {
				t.Fatal(err)
			}
			rule := g.Rulemap["a"]

			m := &tgmachine{
				options: &tgoptions{
					deflateRules:        false,
					deflateNumVals:      false,
					deflateCharVals:     false,
					repetitionThreshold: 256,
				},
				grammar: g,
				buf:     map[string][2][]*Node{},
			}

			i, o, _ := m.repGraph(rule.Alternation.Concatenations[0].Repetitions[0])
			assert.Len(i, tt.ExpectedEntrypoints, "entrypoints")
			assert.Len(o, tt.ExpectedEndpoints, "endpoints")
		})
	}
}

func Test_U_ConcatGraphIO(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input               string
		ExpectedEntrypoints int
		ExpectedEndpoints   int
	}{
		"2-reps": {
			Input:               "a = b *1c",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   2,
		},
		"3-reps": {
			Input:               "a = b *1c *1d",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   3,
		},
		"option-first": {
			Input:               "a = *1b c",
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   1,
		},
		"inner-infinity": {
			Input:               "a = b 2*c d",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"limited-rep": {
			Input:               "a = 1*3b c",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"chained-options": {
			Input:               "a = *1b *1c",
			ExpectedEntrypoints: 3,
			ExpectedEndpoints:   3,
		},
		"repetition-alone": {
			Input:               "a = *b",
			ExpectedEntrypoints: 2, // the emptyNode and b
			ExpectedEndpoints:   2, // the emptyNode and b
		},
		"infinity-and-beyond": {
			Input:               "a = *b c",
			ExpectedEntrypoints: 2, // b and c
			ExpectedEndpoints:   1, // c
		},
		"singularity": {
			Input:               "a = *b *c",
			ExpectedEntrypoints: 3, // the emptyNode, b and c
			ExpectedEndpoints:   3, // the emptyNode, b and c
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := ParseABNF([]byte(tt.Input+"\r\n"), WithValidation(false))
			if !assert.Nil(err) {
				t.Fatal(err)
			}
			rule := g.Rulemap["a"]

			m := &tgmachine{
				options: &tgoptions{
					deflateRules:        false,
					deflateNumVals:      false,
					deflateCharVals:     false,
					repetitionThreshold: 256,
				},
				grammar: g,
				buf:     map[string][2][]*Node{},
			}

			i, o, _ := m.concatGraph(rule.Alternation.Concatenations[0])
			assert.Len(i, tt.ExpectedEntrypoints, "entrypoints")
			assert.Len(o, tt.ExpectedEndpoints, "endpoints")
		})
	}
}

func Test_U_AltGraphIO(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input               string
		ExpectedEntrypoints int
		ExpectedEndpoints   int
	}{
		"a": {
			Input:               "a = *a / b",
			ExpectedEntrypoints: 3,
			ExpectedEndpoints:   3,
		},
		"crlf": {
			Input:               `a = ";" *(b / c) d`,
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
		"option": {
			Input:               `a = b [c / ";"] *d`,
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   4,
		},
		"embed": {
			Input:               `a = [b [c / ";"]]`,
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   4,
		},
		"fuzz_d49a11a8a8e6ebfe": {
			// This fuzz crasher has been kept in the unit tests corpus to ensure
			// the entry-/end-points can reduce to the emptyNode.
			Input:               "a=1*(0(P))",
			ExpectedEntrypoints: 1, // emptyNode
			ExpectedEndpoints:   1, // emptyNode
		},
		"fuzz_982d7689204d140d": {
			// This fuzz crasher enabled detecting an improper I/O piping
			// due to transition graph chaining missing a repetition in case
			// of a (min=1,max=inf) repetition.
			// Through debugging, it also showed the appendNodes implementation
			// should look for all duplicates rather that the emptyNode only.
			Input:               "a=1*(*P)", // (*P) has 2I/2O, then 1*(...) distributes the emptyNode and turn into 3I/3O due to P duplication itself due to minimum cardinality of 1
			ExpectedEntrypoints: 3,
			ExpectedEndpoints:   3,
		},
		"fuzz_982d7689204d140d_variant": {
			// This variant of the fuzz crasher 982d7689204d140d was appended
			// manually rather than detected by the fuzzer. It was a checkup to
			// validate that the error also happened when dealing with a fixed
			// maximum repetition.
			Input:               "a=1*3(*P)",
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   4,
		},
		"empty": {
			// This test case is inherited from the unit test of parsing a grammar
			// that contains an empty char-val.
			Input:               "a=2\"\" a",
			ExpectedEntrypoints: 1,
			ExpectedEndpoints:   1,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := ParseABNF([]byte(tt.Input+"\r\n"), WithValidation(false))
			if !assert.Nil(err) {
				t.Fatal(err)
			}
			rule := g.Rulemap["a"]

			m := &tgmachine{
				options: &tgoptions{
					deflateRules:        false,
					deflateNumVals:      false,
					deflateCharVals:     true,
					repetitionThreshold: 256,
				},
				grammar: g,
				buf:     map[string][2][]*Node{},
			}

			i, o, _ := m.altGraph(rule.Alternation)
			assert.Len(i, tt.ExpectedEntrypoints, "entrypoints")
			assert.Len(o, tt.ExpectedEndpoints, "endpoints")
		})
	}
}
