package goabnf

import (
	"math"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

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

// Test_ParseForest_RepetitionBound covers native counted repetition: an absurd
// but well-formed bound must NOT unroll into the slot grammar. It lowers in O(1)
// and the bound is enforced at parse time, so a huge bound parses promptly and
// the count is still exact. (Previously this DoS was only mitigated by rejecting
// the grammar via the slot budget; it is now handled directly.)
func Test_ParseForest_RepetitionBound(t *testing.T) {
	// Exactly 9999999999 copies: lowers and parses with no error and no DoS;
	// a 1-character input is correctly rejected (one copy is not enough).
	g := mustGrammar("a = 9999999999\"x\"\r\n")
	f, err := ParseForest([]byte("x"), g, "a")
	require.NoError(t, err)
	assert.False(t, f.Valid(), "one copy must not satisfy an exact bound of 9999999999")

	// An unbounded-from-zero huge cap matches a short input promptly.
	g0 := mustGrammar("a = 0*9999999999\"x\"\r\n")
	for in, want := range map[string]bool{"": true, "xxx": true} {
		f, err := ParseForest([]byte(in), g0, "a")
		require.NoErrorf(t, err, "input %q", in)
		assert.Equalf(t, want, f.Valid(), "input %q", in)
	}

	// Legitimate bounded repetition: exact count enforcement.
	g2 := mustGrammar("a = 2*4\"x\"\r\n")
	for in, want := range map[string]bool{"x": false, "xx": true, "xxxx": true, "xxxxx": false} {
		f, err := ParseForest([]byte(in), g2, "a")
		require.NoErrorf(t, err, "input %q", in)
		assert.Equalf(t, want, f.Valid(), "input %q", in)
	}
}

// Test_U_NativeRepetition pins the native counted-repetition semantics that the
// 2-alternate self-recursive lowering plus a parse-time count must satisfy: the
// forest is structurally correct (ambiguity counts), the bound is enforced for a
// variable-width element (the count-conflation guard), and a huge minimum over a
// short input is promptly rejected rather than unrolled.
func Test_U_NativeRepetition(t *testing.T) {
	// Variable-width element under a bounded count. Over "aaa":
	//   count 2: "a"+"aa", "aa"+"a"  -> 2 derivations
	//   count 3: "a"+"a"+"a"         -> 1 derivation
	// All within {2,3}, so the forest must hold exactly 3 trees.
	g := mustGrammar("a = 2*3(\"a\" / \"aa\")\r\n")
	f, err := ParseForest([]byte("aaa"), g, "a")
	require.NoError(t, err)
	require.True(t, f.Valid())
	assert.Equal(t, "3", f.NumTrees().String(), "variable-width {2,3} over aaa")

	// Exactly two copies of a variable-width element over "aaaa": only "aa"+"aa".
	g2 := mustGrammar("a = 2(\"a\" / \"aa\")\r\n")
	f2, err := ParseForest([]byte("aaaa"), g2, "a")
	require.NoError(t, err)
	require.True(t, f2.Valid())
	assert.Equal(t, "1", f2.NumTrees().String(), "exact 2 of a|aa over aaaa")

	// Native repetition must agree with the recognizer across the bound edges.
	for _, tc := range []struct {
		src string
		in  string
	}{
		{"a = 2*3\"a\"\r\n", "a"}, {"a = 2*3\"a\"\r\n", "aa"},
		{"a = 2*3\"a\"\r\n", "aaa"}, {"a = 2*3\"a\"\r\n", "aaaa"},
		{"a = *(1*2\"a\")\r\n", "aaaaa"}, {"a = 1*2(2*3\"a\")\r\n", "aaaaaa"},
	} {
		gg := mustGrammar(tc.src)
		f, err := ParseForest([]byte(tc.in), gg, "a")
		require.NoErrorf(t, err, "%s on %q", tc.src, tc.in)
		rec, err := gg.IsValid("a", []byte(tc.in))
		require.NoErrorf(t, err, "%s on %q", tc.src, tc.in)
		assert.Equalf(t, rec, f.Valid(), "GLL vs recognizer: %s on %q", tc.src, tc.in)
	}

	// Huge minimum, short input: prompt rejection (count enforced at parse time,
	// not unrolled into the grammar).
	gbig := mustGrammar("a = 1000000*\"x\"\r\n")
	fbig, err := ParseForest([]byte("xx"), gbig, "a")
	require.NoError(t, err)
	assert.False(t, fbig.Valid(), "two copies cannot satisfy a minimum of 1000000")
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

// Test_U_NumValOutOfRange covers num-val values beyond U+10FFFF. Such a value is
// a well-formed numeric encoding (legitimate for non-textual / on-wire grammars),
// so without validation ParseABNF accepts it; strict validation rejects it for
// textual use. Using the grammar must never panic. A value, series, or range
// wholly above the Unicode ceiling matches nothing (input is decoded as runes),
// while a range that merely straddles the ceiling matches its Unicode subset.
func Test_U_NumValOutOfRange(t *testing.T) {
	in := []byte("\xf4\x8f\xbf\xbf") // U+10FFFF

	// Cannot match any rune: a lone over-range value, a series whose element is
	// out of range, a range wholly above the ceiling, and a 64-bit value.
	noMatch := []string{
		"a = %x110000\r\n",
		"a = %d1114112\r\n",
		"a = %x10FFFF.110000\r\n",    // series: second element out of range
		"a = %x110000-120000\r\n",    // range wholly above U+10FFFF
		"a = %xBCDE3BCD9AFBCAD3\r\n", // 64-bit value
	}
	for _, src := range noMatch {
		g, err := ParseABNF([]byte(src), WithValidation(false))
		require.NoErrorf(t, err, "src %q must be accepted without validation", src)

		assert.NotPanicsf(t, func() {
			f, perr := ParseForest(in, g, "a")
			require.NoError(t, perr)
			assert.Falsef(t, f.Valid(), "src %q must match nothing", src)
		}, "ParseForest src %q", src)
		assert.NotPanicsf(t, func() {
			v, verr := g.IsValid("a", in)
			require.NoError(t, verr)
			assert.Falsef(t, v, "src %q must match nothing", src)
		}, "IsValid src %q", src)

		// Strict validation rejects it as outside the Unicode range.
		_, err = ParseABNF([]byte(src))
		assert.Errorf(t, err, "src %q must be rejected under validation", src)
	}

	// A range straddling the Unicode ceiling matches its representable subset --
	// here it accepts U+10FFFF on both engines.
	g, err := ParseABNF([]byte("a = %x0-110000\r\n"), WithValidation(false))
	require.NoError(t, err)
	f, perr := ParseForest(in, g, "a")
	require.NoError(t, perr)
	assert.True(t, f.Valid(), "straddling range must match its Unicode subset (GLL)")
	v, verr := g.IsValid("a", in)
	require.NoError(t, verr)
	assert.True(t, v, "straddling range must match its Unicode subset (recognizer)")
	// Strict validation still rejects the out-of-range upper bound.
	_, err = ParseABNF([]byte("a = %x0-110000\r\n"))
	assert.Error(t, err)

	// In-range maximal value still parses and matches.
	g = mustGrammar("a = %x10FFFF\r\n")
	f, err = ParseForest(in, g, "a")
	require.NoError(t, err)
	assert.True(t, f.Valid())
}

// Test_U_NumvalConversion is a white-box test of the generalized num-val
// conversion core. A num-val is a plain non-negative integer, no longer capped at
// the Unicode range: numvalToUint64 parses any 64-bit value (ok=false only on
// real overflow), numvalToInt32 returns the true value when it fits a positive
// int32 and otherwise saturates to MaxInt32 (above every rune, so it can never
// spuriously match), and none of them panic.
func Test_U_NumvalConversion(t *testing.T) {
	t.Run("uint64-parse-and-overflow", func(t *testing.T) {
		cases := []struct {
			str, base string
			want      uint64
			ok        bool
		}{
			{"41", "x", 0x41, true},
			{"1010", "b", 0b1010, true},
			{"65", "d", 65, true},
			{"10FFFF", "x", 0x10FFFF, true},                     // max Unicode
			{"110000", "x", 0x110000, true},                     // just beyond Unicode, still 64-bit
			{"BCDE3BCD9AFBCAD3", "x", 0xBCDE3BCD9AFBCAD3, true}, // 64-bit
			{"FFFFFFFFFFFFFFFF", "x", math.MaxUint64, true},     // exactly 64 bits
			{"1FFFFFFFFFFFFFFFF", "x", 0, false},                // 65 bits -> overflow
			{"zz", "x", 0, false},                               // malformed
		}
		for _, c := range cases {
			got, ok := numvalToUint64(c.str, c.base)
			assert.Equalf(t, c.ok, ok, "ok for %q base %q", c.str, c.base)
			if c.ok {
				assert.Equalf(t, c.want, got, "value for %q base %q", c.str, c.base)
			}
		}
	})

	t.Run("int32-true-value-then-saturation", func(t *testing.T) {
		cases := []struct {
			str, base string
			want      int32
		}{
			{"41", "x", 0x41},
			{"10FFFF", "x", 0x10FFFF},                 // max Unicode, exact
			{"110000", "x", 0x110000},                 // beyond Unicode but fits int32: true value
			{"7FFFFFFF", "x", math.MaxInt32},          // MaxInt32, exact
			{"80000000", "x", math.MaxInt32},          // just over int32 -> saturates
			{"BCDE3BCD9AFBCAD3", "x", math.MaxInt32},  // 64-bit -> saturates
			{"1FFFFFFFFFFFFFFFF", "x", math.MaxInt32}, // overflow -> saturates
		}
		for _, c := range cases {
			assert.NotPanicsf(t, func() {
				assert.Equalf(t, c.want, numvalToInt32(c.str, c.base), "int32 for %q", c.str)
			}, "numvalToInt32 %q", c.str)
		}
	})

	t.Run("rune-and-validity", func(t *testing.T) {
		// At or below the ceiling -> a valid rune; above it -> not a valid rune,
		// which is how matchers reject an out-of-range num-val series.
		assert.True(t, utf8.ValidRune(numvalToRune("10FFFF", "x")))
		assert.False(t, utf8.ValidRune(numvalToRune("110000", "x")))
		assert.False(t, utf8.ValidRune(numvalToRune("BCDE3BCD9AFBCAD3", "x")))
		// A saturated value stays above the Unicode ceiling, so a range using it
		// as an upper bound still covers the whole representable subset.
		assert.Greater(t, numvalToInt32("80000000", "x"), rune(utf8.MaxRune))
	})
}

// Test_U_NumVal_Consumers_NoPanic asserts that every num-val consumer degrades
// gracefully (no panic) on out-of-range values, and that the text producers stay
// faithful: Regex output always compiles, clamping a straddling range to its
// Unicode subset and rendering a wholly-out-of-range value as a never-matching
// class.
func Test_U_NumVal_Consumers_NoPanic(t *testing.T) {
	cases := []struct {
		src           string
		regexCompiles bool
		regexMatchesU bool // does the regex match U+10FFFF?
	}{
		{"a = %x0-110000\r\n", true, true}, // straddling -> Unicode subset
		{"a = %x110000\r\n", true, false},  // lone over-range -> never match
		{"a = %xBCDE3BCD9AFBCAD3\r\n", true, false},
		{"a = %x0-7FFFFFFF\r\n", true, true}, // near MaxInt32, clamped
	}
	u := "\U0010FFFF"
	for _, c := range cases {
		g, err := ParseABNF([]byte(c.src), WithValidation(false))
		require.NoErrorf(t, err, "src %q", c.src)

		assert.NotPanicsf(t, func() {
			re, rerr := g.Regex("a")
			require.NoErrorf(t, rerr, "Regex src %q", c.src)
			compiled, cerr := regexp.Compile("^(?:" + re + ")$")
			assert.Equalf(t, c.regexCompiles, cerr == nil, "Regex %q compiles for src %q", re, c.src)
			if cerr == nil {
				assert.Equalf(t, c.regexMatchesU, compiled.MatchString(u),
					"regex %q match-U+10FFFF for src %q", re, c.src)
			}
		}, "Regex src %q", c.src)

		assert.NotPanicsf(t, func() {
			_, gerr := g.Generate(1, "a")
			_ = gerr
		}, "Generate src %q", c.src)

		// deflate num-vals without deflate rules skips the up-front validation,
		// exercising the enumeration clamp; a near-MaxInt32 range must not hang
		// or bypass the node budget.
		assert.NotPanicsf(t, func() {
			_, terr := g.TransitionGraph("a",
				WithDeflateNumVals(true), WithMaxNodes(1<<16))
			_ = terr
		}, "TransitionGraph src %q", c.src)
	}
}
