package goabnf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The GLL engine parses ANY context-free grammar, including the left-recursive
// grammars the legacy backtracking parser could not handle. Forest.Valid must
// agree with the recognizer (IsValid) on every input.

func Test_ParseForest_LeftRecursion_AgreesWithRecognizer(t *testing.T) {
	cases := map[string]struct {
		abnf string
		rule string
	}{
		"direct-lr":      {"expr = expr \"+\" term / term\r\nterm = 1*DIGIT\r\n", "expr"},
		"direct-lr-tiny": {"a = a \"x\" / \"y\"\r\n", "a"},
		"ambiguous-lr":   {"s = s s \"x\" / \"y\"\r\n", "s"},
		"highly-amb-lr":  {"e = e \"+\" e / e \"*\" e / 1*DIGIT\r\n", "e"},
		"mutual-lr":      {"a = b \"x\" / \"z\"\r\nb = a \"y\" / \"w\"\r\n", "a"},
	}
	alphabet := "+*xyzw0123"
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			g := mustGrammar(tt.abnf)
			// Deterministic enumeration of short inputs.
			for _, in := range enumerate(alphabet, 4) {
				f, err := ParseForest([]byte(in), g, tt.rule)
				require.NoError(t, err)
				want, _ := g.IsValid(tt.rule, []byte(in))
				assert.Equalf(t, want, f.Valid(), "input %q", in)
			}
		})
	}
}

func Test_ParseForest_NonLeftRecursive_Regression(t *testing.T) {
	cases := map[string]struct {
		abnf string
		rule string
	}{
		"fixed-rep":   {"a = 3DIGIT\r\n", "a"},
		"bounded-rep": {"b = 2*4DIGIT\r\n", "b"},
		"nested":      {"c = \"x\" *(\",\" 1*2ALPHA) \"y\"\r\n", "c"},
		"nullable":    {"d = *([\"a\"] \"b\")\r\n", "d"},
	}
	alphabet := "ax,y012b"
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			g := mustGrammar(tt.abnf)
			for _, in := range enumerate(alphabet, 4) {
				f, err := ParseForest([]byte(in), g, tt.rule)
				require.NoError(t, err)
				want, _ := g.IsValid(tt.rule, []byte(in))
				assert.Equalf(t, want, f.Valid(), "input %q", in)
			}
		})
	}
}

// The number of binary parse trees of `e = e "+" e / "1"` over k operands is the
// (k-1)-th Catalan number. This is a precise oracle for SPPF ambiguity packing.
func Test_ParseForest_AmbiguityCount_Catalan(t *testing.T) {
	g := mustGrammar("e = e \"+\" e / \"1\"\r\n")
	catalan := []int64{1, 1, 2, 5, 14, 42, 132, 429}
	for ops := 1; ops <= 7; ops++ {
		in := strings.TrimRight(strings.Repeat("1+", ops), "+")
		f, err := ParseForest([]byte(in), g, "e")
		require.NoError(t, err)
		require.True(t, f.Valid())
		// Ambiguous iff there is more than one parse tree. With k operands the
		// count is the (k-1)-th Catalan number, so ambiguity begins at k=3.
		assert.Equalf(t, catalan[ops-1] > 1, f.Ambiguous(), "operands=%d", ops)
		assert.Equalf(t, catalan[ops-1], f.NumTrees().Int64(), "operands=%d", ops)
	}
}

// An infinitely-ambiguous grammar yields a cyclic forest; NumTrees reports -1.
func Test_ParseForest_InfiniteAmbiguity(t *testing.T) {
	g := mustGrammar("a = a / \"x\"\r\n")
	f, err := ParseForest([]byte("x"), g, "a")
	require.NoError(t, err)
	assert.True(t, f.Valid())
	assert.True(t, f.Ambiguous())
	assert.Equal(t, int64(-1), f.NumTrees().Int64())
	// Tree extraction must still terminate on a cyclic forest.
	assert.NotNil(t, f.Tree())
}

func Test_ParseForest_NodeBudget(t *testing.T) {
	g := mustGrammar("list = num *(\",\" num)\r\nnum = 1*DIGIT\r\n")
	parts := make([]string, 200)
	for i := range parts {
		parts[i] = "7"
	}
	in := []byte(strings.Join(parts, ","))

	_, err := ParseForest(in, g, "list", WithMaxForestNodes(1000))
	require.Error(t, err)
	assert.IsType(t, &ErrForestTooLarge{}, err)

	f, err := ParseForest(in, g, "list")
	require.NoError(t, err)
	assert.True(t, f.Valid())
}

// The GLL engine must parse the ABNF meta-grammar itself, agreeing with the
// recognizer, and recover a rule-rooted tree spanning the whole input.
func Test_ParseForest_MetaGrammar(t *testing.T) {
	inputs := []string{
		"a = \"x\"\r\n",
		"rule = ALPHA *(ALPHA / DIGIT)\r\n",
		"foo = 1*3(\"a\" / \"b\") [\",\"]\r\n",
		"x = %x41-5A\r\n",
		"crlf = %x0D.0A\r\n",
	}
	for _, in := range inputs {
		f, err := ParseForest([]byte(in), ABNF, "rulelist")
		require.NoErrorf(t, err, "input %q", in)
		want, _ := ABNF.IsValid("rulelist", []byte(in))
		assert.Equalf(t, want, f.Valid(), "input %q", in)
		assert.Falsef(t, f.Ambiguous(), "ABNF must be unambiguous, input %q", in)

		tree := f.Tree()
		require.NotNilf(t, tree, "input %q", in)
		assert.Equal(t, "rulelist", tree.Rule)
		assert.Equal(t, 0, tree.Start)
		assert.Equalf(t, len(in), tree.End, "tree must span the whole input, %q", in)
	}
}

func Test_ParseForest_UnknownRoot(t *testing.T) {
	g := mustGrammar("a = \"x\"\r\n")
	_, err := ParseForest([]byte("x"), g, "nope")
	require.Error(t, err)
	assert.IsType(t, &ErrRuleNotFound{}, err)
}

// enumerate returns every string of length 0..maxLen over the given alphabet.
func enumerate(alphabet string, maxLen int) []string {
	out := []string{""}
	frontier := []string{""}
	for l := 0; l < maxLen; l++ {
		var next []string
		for _, p := range frontier {
			for _, c := range alphabet {
				s := p + string(c)
				out = append(out, s)
				next = append(next, s)
			}
		}
		frontier = next
	}
	return out
}

// Test_ParseForest_RepetitionBoundDoS guards the lowering DoS: an absurd but
// well-formed repetition bound must be rejected by the slot budget instead of
// unrolling into billions of nonterminals (or overflowing the stack).
func Test_ParseForest_RepetitionBoundDoS(t *testing.T) {
	g := mustGrammar("a = 9999999999\"x\"\r\n")
	_, err := ParseForest([]byte("x"), g, "a")
	require.Error(t, err)
	assert.IsType(t, &ErrGrammarTooLarge{}, err)

	// A caller that really wants it can raise the budget; legitimate bounded
	// repetitions stay well within the default.
	g2 := mustGrammar("a = 2*4\"x\"\r\n")
	for in, want := range map[string]bool{"x": false, "xx": true, "xxxx": true, "xxxxx": false} {
		f, err := ParseForest([]byte(in), g2, "a")
		require.NoErrorf(t, err, "input %q", in)
		assert.Equalf(t, want, f.Valid(), "input %q", in)
	}
}

// Test_ParseForest_UnsatisfiableBound checks that a max < min repetition is the
// empty language (unsatisfiable), not an unbounded one. Built as a literal
// because ParseABNF's default validation rejects min > max.
func Test_ParseForest_UnsatisfiableBound(t *testing.T) {
	g := &Grammar{Rulemap: map[string]*Rule{
		"a": {
			Name: "a",
			Alternation: Alternation{Concatenations: []Concatenation{{
				Repetitions: []Repetition{{
					Min: 3, Max: 2,
					Element: ElemCharVal{Values: []rune{'a'}},
				}},
			}}},
		},
	}}
	for _, in := range []string{"", "a", "aa", "aaa", "aaaa", "aaaaa"} {
		f, err := ParseForest([]byte(in), g, "a")
		require.NoErrorf(t, err, "input %q", in)
		assert.Falsef(t, f.Valid(), "max<min must accept nothing, input %q", in)
	}
}

// Test_U_NumValOutOfRange covers the out-of-Unicode-range num-val hardening: a
// num-val above U+10FFFF is not representable, so ParseABNF rejects it even with
// validation disabled, and neither the recognizer nor the GLL engine panics on a
// hand-built grammar carrying such a value -- both treat it as non-matching.
func Test_U_NumValOutOfRange(t *testing.T) {
	for _, src := range []string{
		"a = %x110000\r\n",
		"a = %x0-110000\r\n",
		"a = %d1114112\r\n",
		"a = %x10FFFF.110000\r\n",
	} {
		_, err := ParseABNF([]byte(src), WithValidation(false))
		assert.Errorf(t, err, "src %q must be rejected even without validation", src)
		_, err = ParseABNF([]byte(src))
		assert.Errorf(t, err, "src %q must be rejected", src)
	}

	// In-range maximal values still parse.
	for _, src := range []string{"a = %x10FFFF\r\n", "a = %x0-10FFFF\r\n", "a = %d1114111\r\n"} {
		_, err := ParseABNF([]byte(src))
		assert.NoErrorf(t, err, "src %q", src)
	}

	// A hand-built grammar (bypassing ParseABNF's invariant) with an out-of-range
	// num-val must not panic either engine.
	g := &Grammar{Rulemap: map[string]*Rule{
		"a": {Name: "a", Alternation: Alternation{Concatenations: []Concatenation{{
			Repetitions: []Repetition{{Min: 1, Max: 1, Element: ElemNumVal{
				Base: "x", Status: StatRange, Elems: []string{"0", "110000"},
			}}},
		}}}},
	}}
	in := []byte("\xf4\x8f\xbf\xbf")
	assert.NotPanics(t, func() {
		f, err := ParseForest(in, g, "a")
		require.NoError(t, err)
		assert.False(t, f.Valid())
	})
	assert.NotPanics(t, func() {
		v, err := g.IsValid("a", in)
		require.NoError(t, err)
		assert.False(t, v)
	})
}
