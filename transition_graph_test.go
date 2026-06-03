package goabnf

import (
	_ "embed"
	"errors"
	"testing"
	"time"

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
			// Outer optional is skippable, so the empty string is producible
			// even though b and c are undefined (the empty path needs neither).
			Input:                `a = [b [c / ";"]]`,
			ExpectedCombinations: [][]byte{{}},
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
			}

			if tt.ExpectedCombinations != nil {
				assert.ElementsMatch(tt.ExpectedCombinations, elems)
			} else {
				assert.Equal(tt.ExpectedNumerCombinations, len(elems))
			}
		})
	}
}

// drain reads a reader to completion (or until cap) within a deadline. It
// returns the number of strings produced and whether it terminated naturally.
// The whole point of the coverage rewrite is that this never hangs.
func drain(t *testing.T, r *TransitionGraphReader, cap int) (int, bool) {
	t.Helper()
	done := make(chan [2]int, 1)
	go func() {
		n := 0
		for r.Next() {
			r.Scan()
			n++
			if n > cap {
				done <- [2]int{n, 0}
				return
			}
		}
		done <- [2]int{n, 1}
	}()
	select {
	case res := <-done:
		return res[0], res[1] == 1
	case <-time.After(20 * time.Second):
		t.Fatal("reader did not terminate within 20s (DoS)")
		return 0, false
	}
}

func tg(t *testing.T, src string, opts ...TGOption) *TransitionGraph {
	t.Helper()
	g, err := ParseABNF([]byte(src))
	if err != nil {
		t.Fatalf("ParseABNF(%q): %v", src, err)
	}
	graph, err := g.TransitionGraph("s", opts...)
	if err != nil {
		t.Fatalf("TransitionGraph: %v", err)
	}
	return graph
}

// Mode B (compact) must terminate with a small set for every (grammar x option)
// combination. Before the rewrite, 11 of these hung (infinite recursion /
// unbounded walk) under the single reader that existed.
func Test_U_TGReader_CompactAlwaysBounded(t *testing.T) {
	t.Parallel()
	srcs := []string{
		"s = \"a\" / \"b\"\r\n",
		"s = *\"a\"\r\n",
		"s = *(\"a\" / \"b\")\r\n",
		"s = *(\"ab\")\r\n",
		"s = 1*2(\"a\" / \"b\")\r\n",
		"s = *(\"x\" / (\"y\" [\"z\"]))\r\n",
		"s = ALPHA *(ALPHA / DIGIT)\r\n",
		"s = 2\"ab\" %x20 \"z\"\r\n",
	}
	opts := [][]TGOption{
		nil,
		{WithDeflateRules(true)},
		{WithDeflateNumVals(true)},
		{WithDeflateCharVals(true)},
	}
	for _, src := range srcs {
		for _, o := range opts {
			graph := tg(t, src, o...)
			// Mode B (compact) is the universal guarantee: it always terminates
			// and stays small, for every grammar -- including the dense ones where
			// mode A's trail x variation product is astronomically large (finite,
			// but not something you want to enumerate). That mode-A size is exactly
			// why mode B exists, so we do NOT assert mode A terminates quickly here.
			n, ok := drain(t, graph.Reader(WithCoverageMode(CoverageCompact)), 1_000_000)
			if !ok {
				t.Errorf("mode B did not terminate for %q", src)
			}
			if n > 100_000 {
				t.Errorf("mode B produced %d strings for %q; expected a compact set", n, src)
			}
		}
	}
}

// The previously-DoSing case now yields a finite covering set in both modes.
func Test_U_TGReader_CyclicMultiNode_NoDoS(t *testing.T) {
	t.Parallel()
	graph := tg(t, "s = *(\"ab\")\r\n", WithDeflateCharVals(true))

	nA, okA := drain(t, graph.Reader(), 5_000_000)
	if !okA {
		t.Fatal("mode A hung on *(\"ab\") deflateCharVals")
	}
	if nA == 0 {
		t.Fatal("mode A produced nothing")
	}

	// Mode B must cover all 8 edges with a handful of strings.
	r := graph.Reader(WithCoverageMode(CoverageCompact))
	got := map[string]bool{}
	for r.Next() {
		got[string(r.Scan())] = true
	}
	// One representative covering set is {"", AB, abab, abAb, aBab, aBAb};
	// assert it is small and contains the empty string and the four 1-rep heads
	// that exercise the forward edges.
	if len(got) == 0 || len(got) > 64 {
		t.Fatalf("mode B set size %d out of expected range", len(got))
	}
	if !got[""] {
		t.Error("mode B did not emit the empty string")
	}
}

// Mode A reproduces the historical coverage counts exactly.
func Test_U_TGReader_ModeA_KnownCounts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		src  string
		want int
	}{
		{"s = \"a\" / \"b\"\r\n", 4},
		{"s = *\"a\"\r\n", 7},
		{"s = *(\"ab\")\r\n", 21},
	}
	for _, c := range cases {
		graph := tg(t, c.src)
		n, ok := drain(t, graph.Reader(), 1_000_000)
		if !ok {
			t.Fatalf("%q did not terminate", c.src)
		}
		if n != c.want {
			t.Errorf("%q: mode A produced %d, want %d", c.src, n, c.want)
		}
	}
}

// WithMaxNodes must be unbounded by default (backward compatible) and, when set,
// must reject grammars whose construction would exceed the budget -- including
// the nested-repetition and wide-num-val-range blow-ups that
// WithRepetitionThreshold does not catch -- with a typed *ErrMaxNodesExceeded.
func Test_U_TransitionGraph_MaxNodes(t *testing.T) {
	t.Parallel()

	// Default is unbounded: a moderately nested repetition still builds.
	if _, err := mustGrammar("a = 10(10(\"x\"))\r\n").TransitionGraph("a"); err != nil {
		t.Fatalf("default (unbounded) should build 10(10(\"x\")): %v", err)
	}

	// Bounded: the same shape, scaled up, must be rejected with the typed error.
	_, err := mustGrammar("a = 100(100(100(\"x\")))\r\n").TransitionGraph("a", WithMaxNodes(10_000))
	var budgetErr *ErrMaxNodesExceeded
	if !errors.As(err, &budgetErr) {
		t.Fatalf("nested reps over budget: got %v, want *ErrMaxNodesExceeded", err)
	}

	// Wide num-val range deflation is bounded too.
	_, err = mustGrammar("a = %x00-10FFFF\r\n").TransitionGraph("a",
		WithDeflateNumVals(true), WithMaxNodes(1_000))
	if !errors.As(err, &budgetErr) {
		t.Fatalf("wide deflated range over budget: got %v, want *ErrMaxNodesExceeded", err)
	}

	// A budget large enough for a normal grammar lets it build.
	if _, err := mustGrammar("a = *(\"a\" / \"b\")\r\n").TransitionGraph("a", WithMaxNodes(1_000)); err != nil {
		t.Fatalf("normal grammar under a generous budget: %v", err)
	}

	// A non-positive budget means unbounded.
	if _, err := mustGrammar("a = 10(10(\"x\"))\r\n").TransitionGraph("a", WithMaxNodes(0)); err != nil {
		t.Fatalf("MaxNodes(0) should be unbounded: %v", err)
	}
}
