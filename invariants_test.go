package goabnf

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file stitches the metamorphic relations that go-abnf relies on to be a
// trustworthy oracle into standing CI checks. They are the same cross-checks the
// engines were validated against during development; pinning them here turns
// "we tested it once" into "a regression fails the build".
//
// Relations asserted:
//   - the recognizer (IsValid), the SPPF forest (ParseForest) and the BSR set
//     (ParseBSR) agree on validity for every grammar/input;
//   - ParseForest and ParseBSR agree on NumTrees and Ambiguous (forest shape,
//     not just acceptance);
//   - for regular grammars, Regex compiled and anchored matches IsValid;
//   - every input produced by Generate is accepted by IsValid (generation is
//     sound w.r.t. recognition);
//   - ParseABNF(g.String()) round-trips to a stable canonical form.

type invariantCase struct {
	name    string
	src     string
	alpha   string
	maxn    int
	regular bool // true => Regex must equal IsValid (no recursion)
}

var invariantCorpus = []invariantCase{
	{"star", `a = *"a"`, "a", 6, true},
	{"plus_alt", `a = 1*("a" / "b")`, "ab", 5, true},
	{"context", `a = "x" 2*3"y"`, "xy", 6, true},
	{"varwidth", `a = 2*3("a" / "aa")`, "a", 7, false},
	{"nullable", `a = 2*3("a" / "")`, "a", 4, false},
	{"nested", `a = 1*2(2*3"a")`, "a", 8, false},
	{"catalan", `a = a a / "a"`, "a", 6, false}, // Catalan ambiguity
	{"leftrec", `a = a "a" / "a"`, "a", 6, false},
	{"infamb", `a = a / "a"`, "a", 3, false}, // infinitely ambiguous (-1)
}

// enumerate returns every string over alpha up to length max (inclusive).
func enumerate(alpha string, max int) []string {
	out := []string{""}
	cur := []string{""}
	for l := 1; l <= max; l++ {
		var next []string
		for _, p := range cur {
			for _, c := range alpha {
				next = append(next, p+string(c))
			}
		}
		out = append(out, next...)
		cur = next
	}
	return out
}

// Test_I_Engines_Agree pins recognizer == SPPF == BSR on validity, and SPPF ==
// BSR on tree count and ambiguity, plus Regex == IsValid for regular grammars.
func Test_I_Engines_Agree(t *testing.T) {
	for _, c := range invariantCorpus {
		c := c
		t.Run(c.name, func(t *testing.T) {
			g := mustGrammar(c.src + "\r\n")

			var re *regexp.Regexp
			if c.regular {
				pat, err := g.Regex("a")
				require.NoErrorf(t, err, "Regex(%q)", c.src)
				re = regexp.MustCompile("^(?:" + pat + ")$")
			}

			for _, in := range enumerate(c.alpha, c.maxn) {
				rec, err := g.IsValid("a", []byte(in))
				require.NoErrorf(t, err, "IsValid %q", in)
				sf, err := ParseForest([]byte(in), g, "a")
				require.NoErrorf(t, err, "ParseForest %q", in)
				bf, err := ParseBSR([]byte(in), g, "a")
				require.NoErrorf(t, err, "ParseBSR %q", in)

				assert.Equalf(t, rec, sf.Valid(), "recognizer vs SPPF on %q", in)
				assert.Equalf(t, rec, bf.Valid(), "recognizer vs BSR on %q", in)
				assert.Equalf(t, sf.NumTrees().String(), bf.NumTrees().String(),
					"SPPF vs BSR NumTrees on %q", in)
				assert.Equalf(t, sf.Ambiguous(), bf.Ambiguous(), "SPPF vs BSR Ambiguous on %q", in)
				if re != nil {
					assert.Equalf(t, rec, re.MatchString(in), "Regex vs IsValid on %q", in)
				}
			}
		})
	}
}

// Test_I_Generate_IsValid pins that generation is sound: every input Generate
// produces from a grammar is accepted by that grammar's recognizer.
func Test_I_Generate_IsValid(t *testing.T) {
	for _, c := range invariantCorpus {
		c := c
		t.Run(c.name, func(t *testing.T) {
			g := mustGrammar(c.src + "\r\n")
			for seed := int64(0); seed < 40; seed++ {
				out, err := g.Generate(seed, "a", WithRepMax(6), WithThreshold(64))
				if err != nil {
					continue // unsatisfiable seed/limits; not a soundness failure
				}
				ok, err := g.IsValid("a", out)
				require.NoErrorf(t, err, "IsValid on generated %q (seed %d)", out, seed)
				assert.Truef(t, ok, "generated input %q (seed %d) must be valid", out, seed)
			}
		})
	}
}

// Test_I_String_Idempotent pins that a grammar serialises to ABNF that reparses
// to the same canonical form.
func Test_I_String_Idempotent(t *testing.T) {
	for _, c := range invariantCorpus {
		c := c
		t.Run(c.name, func(t *testing.T) {
			g := mustGrammar(c.src + "\r\n")
			g2, err := ParseABNF([]byte(g.String()), WithValidation(false))
			require.NoErrorf(t, err, "reparse of String() for %q", c.src)
			assert.Equal(t, g.String(), g2.String(), "String() must be idempotent")
		})
	}
}
