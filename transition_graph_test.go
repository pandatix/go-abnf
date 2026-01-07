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
			Input:               "a=1*(*P)", // (*P) has 2I/2O, then 1*(...) distributes the emptyNode and P, but as both where already terminal nodes it changes nothing
			ExpectedEntrypoints: 2,
			ExpectedEndpoints:   2,
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

func Test_U_TransitionGraphExhaustiveCombinations(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		// Input is an ABNF grammar.
		// No need to add the trailing CRLF characters.
		Input string

		// ExpectedCombinations is the list of all expected combinations
		// generated from travaling through the Transition Graph of a
		// given Grammar.
		ExpectedCombinations [][]byte

		// ExpectedNumberCombinations override ExpectedCombinations.
		// It defines the number of combinations expected from traveling
		// through the Transition Graph of a given Grammar.
		// The outcomes might be unpredictable as depends on the travel
		// approach (e.g. DFS, BFS), but their number remains invariant.
		ExpectedNumerCombinations int
	}{
		"single": {
			Input: "a = \"a\"",
			ExpectedCombinations: [][]byte{
				[]byte("a"),
				[]byte("A"),
			},
		},
		"optional": {
			Input: "a = [\"a\"]",
			ExpectedCombinations: [][]byte{
				[]byte("a"),
				[]byte("A"),
				[]byte(""),
			},
		},
		"single-alternative": {
			Input: "a = \"a\" / \"b\"",
			ExpectedCombinations: [][]byte{
				[]byte("a"),
				[]byte("A"),
				[]byte("b"),
				[]byte("B"),
			},
		},
		"concatenation": {
			Input: "a = \"a\" \"b\"",
			ExpectedCombinations: [][]byte{
				[]byte("ab"),
				[]byte("aB"),
				[]byte("Ab"),
				[]byte("AB"),
			},
		},
		"0-n-sensitive": {
			Input: "a = 0*3%s\"a\"",
			ExpectedCombinations: [][]byte{
				[]byte(""),
				[]byte("a"),
				[]byte("aa"),
				[]byte("aaa"),
			},
		},
		"numval-range": {
			Input: "a = %x61-63",
			ExpectedCombinations: [][]byte{
				[]byte("a"),
				[]byte("b"),
				[]byte("c"),
			},
		},
		"0-n": {
			Input: "a = 0*3\"a\"",
			ExpectedCombinations: [][]byte{
				[]byte(""),
				[]byte("a"),
				[]byte("A"),
				[]byte("aa"),
				[]byte("aA"),
				[]byte("Aa"),
				[]byte("AA"),
				[]byte("aaa"),
				[]byte("aaA"),
				[]byte("aAa"),
				[]byte("aAA"),
				[]byte("Aaa"),
				[]byte("AaA"),
				[]byte("AAa"),
				[]byte("AAA"),
			},
		},
		"1-inf": {
			Input:                "a = 1*\"a\"",
			ExpectedCombinations: nil,
			ExpectedNumerCombinations: len([][]byte{
				[]byte("a"),
				[]byte("A"),
				[]byte("aa"),
				[]byte("aA"),
				[]byte("Aa"),
				[]byte("AA"),
			}),
		},
		"embeded-loop": {
			Input: "a = %s\"a\" 1*%s\"b\" %s\"c\"",
			ExpectedCombinations: [][]byte{
				[]byte("abc"),
				[]byte("abbc"),
			},
		},
		"embeded-loop-insensitive": {
			Input: "a = %s\"a\" 1*\"b\" \"c\"",
			ExpectedCombinations: [][]byte{
				[]byte("abc"),
				[]byte("aBc"),
				[]byte("abbc"),
				[]byte("abBc"),
				[]byte("aBbc"),
				[]byte("aBBc"),
				[]byte("abC"),
				[]byte("aBC"),
				[]byte("abbC"),
				[]byte("abBC"),
				[]byte("aBbC"),
				[]byte("aBBC"),
			},
		},
		"embed": {
			// No semantic validation AND rules not defined (nor deflated) -> no combinations
			Input:                `a = [b [c / ";"]]`,
			ExpectedCombinations: [][]byte{},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := ParseABNF([]byte(tt.Input+"\r\n"), WithValidation(false))
			if !assert.Nil(err) {
				return
			}

			tg, err := g.TransitionGraph("a")
			if !assert.Nil(err) {
				return
			}

			r := tg.Reader()
			elems := [][]byte{}
			for r.Next() {
				elems = append(elems, r.Scan())

				if len(elems) > 32 {
					break // virtually skip if infinite loop, no need to wait for the timeout
				}
			}

			if tt.ExpectedCombinations != nil {
				assert.ElementsMatch(tt.ExpectedCombinations, elems)
			} else {
				assert.Equal(tt.ExpectedNumerCombinations, len(elems))
			}
		})
	}
}
