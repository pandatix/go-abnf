package goabnf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The BSR engine (bsr.go) is an alternative derivation representation to the
// SPPF. It must agree with the SPPF engine on Valid, NumTrees and Ambiguous, and
// with the recognizer on Valid, for every grammar and input.

func Test_U_BSR_AgreesWithSPPF(t *testing.T) {
	type gc struct {
		src, alpha string
		maxn       int
	}
	cases := []gc{
		{`a = *"a"`, "a", 6},
		{`a = 2*5"a"`, "a", 6},
		{`a = 2*3("a" / "aa")`, "a", 7}, // variable-width under a bound
		{`a = *("a" / "aa")`, "a", 7},
		{`a = 2*3("a" / "")`, "a", 4}, // nullable element
		{`a = 1*2(2*3"a")`, "a", 8},   // nested repetition
		{`a = a a / "a"`, "a", 6},     // Catalan ambiguity
		{`a = a "a" / "a"`, "a", 6},   // left recursion
		{`a = a / "a"`, "a", 3},       // infinitely ambiguous
		{`a = ("a" "b" "c") / "abc"`, "abc", 3},
	}
	for _, c := range cases {
		g := mustGrammar(c.src + "\r\n")
		// enumerate all strings over alpha up to maxn
		cur := []string{""}
		all := []string{""}
		for l := 1; l <= c.maxn; l++ {
			var nxt []string
			for _, p := range cur {
				for _, ch := range c.alpha {
					nxt = append(nxt, p+string(ch))
				}
			}
			all = append(all, nxt...)
			cur = nxt
		}
		for _, in := range all {
			sf, serr := ParseForest([]byte(in), g, "a")
			require.NoErrorf(t, serr, "%s sppf %q", c.src, in)
			bf, berr := ParseBSR([]byte(in), g, "a")
			require.NoErrorf(t, berr, "%s bsr %q", c.src, in)
			rv, _ := g.IsValid("a", []byte(in))

			assert.Equalf(t, sf.Valid(), bf.Valid(), "Valid %s on %q", c.src, in)
			assert.Equalf(t, rv, bf.Valid(), "BSR vs recognizer %s on %q", c.src, in)
			assert.Equalf(t, sf.NumTrees().String(), bf.NumTrees().String(),
				"NumTrees %s on %q", c.src, in)
			assert.Equalf(t, sf.Ambiguous(), bf.Ambiguous(), "Ambiguous %s on %q", c.src, in)
		}
	}
}

func Test_U_BSR_Tree(t *testing.T) {
	g := mustGrammar("ip = 1*3DIGIT 3(\".\" 1*3DIGIT)\r\n")
	bf, err := ParseBSR([]byte("12.34.56.78"), g, "ip")
	require.NoError(t, err)
	require.True(t, bf.Valid())
	tr := bf.Tree()
	require.NotNil(t, tr)
	assert.Equal(t, "ip", tr.Rule)
	assert.Equal(t, 0, tr.Start)
	assert.Equal(t, len("12.34.56.78"), tr.End)

	// Invalid input yields no tree.
	bad, err := ParseBSR([]byte("12.34.56"), g, "ip")
	require.NoError(t, err)
	assert.False(t, bad.Valid())
	assert.Nil(t, bad.Tree())
}

func Test_U_BSR_HugeRepetitionBoundNoDoS(t *testing.T) {
	// Native counted repetition carries to the BSR engine: a huge bound lowers
	// in O(1) and parses promptly; the count is still enforced exactly.
	g := mustGrammar("a = 0*9999999999\"x\"\r\n")
	f, err := ParseBSR([]byte(strings.Repeat("x", 5)), g, "a")
	require.NoError(t, err)
	assert.True(t, f.Valid())

	g2 := mustGrammar("a = 1000000*\"x\"\r\n")
	f2, err := ParseBSR([]byte("xx"), g2, "a")
	require.NoError(t, err)
	assert.False(t, f2.Valid(), "two copies cannot satisfy a minimum of 1000000")
}
