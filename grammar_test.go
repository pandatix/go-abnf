package goabnf

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/void.abnf
var voidAbnf []byte

//go:embed testdata/atomic.abnf
var atomicAbnf []byte

//go:embed testdata/platypus.abnf
var platypusAbnf []byte

//go:embed testdata/fun.abnf
var funAbnf []byte

//go:embed testdata/noob.abnf
var noobAbnf []byte

//go:embed testdata/rulelist.abnf
var rulelistAbnf []byte

//go:embed testdata/rule.abnf
var ruleAbnf []byte

//go:embed testdata/element.abnf
var elementAbnf []byte

//go:embed testdata/multi.abnf
var multiAbnf []byte

//go:embed testdata/abnf.abnf
var abnfAbnf []byte

//go:embed testdata/fixed-abnf.abnf
var fixedAbnfAbnf []byte

//go:embed testdata/fixed-abnf-raw.abnf
var fixedAbnfRawAbnf []byte

//go:embed testdata/aftn.abnf
var aftnAbnf []byte

//go:embed testdata/fuzz_regex_eaa469604868c87f.abnf
var fuzzRegex_eaa469604868c87fAbnf []byte

//go:embed testdata/redefine.abnf
var redefineAbnf []byte

//go:embed testdata/toml.abnf
var tomlAbnf []byte

var testsParseAbnf = map[string]struct {
	Input     []byte
	Validate  bool
	Redefine  bool
	ExpectErr bool
}{
	"void": {
		Input:     voidAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"atomic": {
		Input:     atomicAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"platypus": {
		Input:     platypusAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"fun": {
		Input:     funAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"noob": {
		Input:     noobAbnf,
		Validate:  false,
		ExpectErr: true, // Due to LF (expected CRLF)
	},
	"rulelist": {
		Input:     rulelistAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"rule": {
		Input:     ruleAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"element": {
		Input:     elementAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"multi": {
		Input:     multiAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"abnf": {
		// This test validates we can parse ABNF using ABNF grammar
		// and the ABNF structural model :)
		Input:     abnfAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"fixed-abnf": {
		// This test validates we can parse ABNF once fixed by erratum
		// 2968+3076 and RFC 7405 using ABNF grammar and the ABNF
		// structural mode :))
		Input:     fixedAbnfAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"fixed-abnf-raw": {
		Input:     fixedAbnfRawAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"aftn": {
		Input:     aftnAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_9de7f1cac25b4c59": {
		// This fuzz crasher enabled detecting invalid repetition's repeat
		// min/max values extraction.
		Input:     []byte("A=012(\"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_9de7f1cac25b4c59 variant 1": {
		Input:     []byte("A=*012(\"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_9de7f1cac25b4c59 variant 2": {
		Input:     []byte("A=012*(\"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_6c652486622bc04e": {
		// This fuzz crasher enabled detecting bad group's alternation
		// extraction.
		Input:     []byte("A=(  \"\")\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_395eb15ada9c6900": {
		// This fuzz crasher enabled detecting missing prose-val evaluation support.
		Input:     []byte("A=<>\r\n"),
		Validate:  false,
		ExpectErr: false,
	},
	"Fuzz_eaa469604868c87f": {
		// This fuzz crasher enabled detecting a mis-undhandling of the defined-as character.
		Input:     fuzzRegex_eaa469604868c87fAbnf,
		Validate:  false,
		ExpectErr: false,
	},
	"binary-maximal": {
		Input:     []byte("a = %b0-100001111111111111111\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"binary-out": {
		Input:     []byte("a = %b0-100010000000000000000\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"decimal-maximal": {
		Input:     []byte("a = %d0-1114111\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"decimal-out": {
		Input:     []byte("a = %d0-1114112\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"hexadecimal-maximal": {
		Input:     []byte("a = %x0-10FFFF\r\n"),
		Validate:  true,
		ExpectErr: false,
	},
	"hexadecimal-out": {
		Input:     []byte("a = %x0-110000\r\n"),
		Validate:  true,
		ExpectErr: true,
	},
	"redefine": {
		// This tests for behavioral retrocompatiblity
		Input:     redefineAbnf,
		Redefine:  false, // default behavior
		ExpectErr: true,
	},
	"redefine-granted": {
		Input:     redefineAbnf,
		Redefine:  true,
		ExpectErr: false,
	},
	"toml": {
		// Issue #105 shows the implementation did not cover large enough values.
		// num-values were generated over a single byte, which made it impossible
		// to handle unicode characters, e.g., emojis.
		Input:     tomlAbnf,
		Redefine:  true, // at the end ABNF core rules are reproduced
		Validate:  true, // should be valid
		ExpectErr: false,
	},
}

func Test_U_ParseABNF(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseAbnf {
		t.Run(testname, func(t *testing.T) {
			require.NotEmpty(t, tt.Input)
			g, err := ParseABNF(tt.Input,
				WithValidation(tt.Validate),
				WithRedefineCoreRules(tt.Redefine),
			)
			_ = g

			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected err: %t ; got: %s", tt.ExpectErr, err)
			}
		})
	}
}

func Test_U_ABNFParseItself(t *testing.T) {
	t.Parallel()

	// Test the hardcoded ABNF is:
	// - valid (string method works)
	// - complete (ABNF representation of ABNF can be parsed by ABNF)
	hardcoded := ABNF.String()
	g, err := ParseABNF([]byte(hardcoded))
	require.NoError(t, err)

	// Test the generated ABNF from the hardcoded ABNF is also:
	// - valid (string method works)
	// - complete (ABNF representation of ABNF can be parsed by ABNF)
	// (1a) with the hardcoded ABNF grammar
	fresh := g.String()
	ng, err := ParseABNF([]byte(fresh))
	assert.Equal(t, g, ng)
	assert.Nil(t, err)

	assert.Equal(t, ABNF, ng)

	// 1b (with the freshly produced ABNF grammar)
	sol, err := Parse([]byte(fresh), g, "rulelist")
	assert.NotNil(t, sol)
	assert.Nil(t, err)
}

func Test_U_ParseRootNonGroup(t *testing.T) {
	// Issue #32 use case is a root rule that does not start
	// with a group as its first root alternation element.
	assert := assert.New(t)

	// First we build our grammar
	g, err := ParseABNF(platypusAbnf)
	if !assert.Nil(err) {
		return
	}

	// Then we consider an input, valid according to our grammar.
	input := []byte("a")
	p, err := Parse(input, g, "b")
	if !assert.Nil(err) {
		return
	}

	// Then we make sure there is only 1 possibility, and all
	// subpaths have the proper name.
	if !assert.Len(p, 1) {
		return
	}
	assert.Equal("b", p[0].MatchRule)
	assert.Equal("a", p[0].Subpaths[0].MatchRule)
}

func Test_U_ParseEmptyCharVal(t *testing.T) {
	// Issue #103 use case is to parse an empty char-val.
	// In that situation the evaluator would extract a non-empty character
	// leading post-processing operations inadequate.
	{
		g, err := ParseABNF([]byte("a=\"\"\r\n"))
		require.NoError(t, err)

		a := g.Rulemap["a"]
		assert.Empty(t, a.Alternation.Concatenations[0].Repetitions[0].Element.(ElemCharVal).Values)
	}

	// Issue #206 documents the empty char-val in an infinite-upper-bounded repetition.
	// It shows that due to the assumption of a char-val is at least one character long,
	// solving the element of such rule connsumes a non-empty part of the input. Though, in
	// the context of an empty char-val, such loop never ends yet no iteration produces new
	// valid paths of evaluation.
	{
		g, err := ParseABNF([]byte("a=*\"\"\r\n"))
		require.NoError(t, err)

		_, err = Parse([]byte("test"), g, "a") // This had an infinite loop
		assert.NoError(t, err)
	}

	// The following test case is for regression detection
	{
		g, err := ParseABNF([]byte("a=\"abc\"\r\n"))
		require.NoError(t, err)

		a := g.Rulemap["a"]
		bs := a.Alternation.Concatenations[0].Repetitions[0].Element.(ElemCharVal).Values
		assert.Equal(t, "abc", string(bs))
	}
}

var (
	//go:embed testdata/issue189.abnf
	issue189 []byte
)

func Test_U_ParseEndingRepeat0(t *testing.T) {
	// Issue #189 use case is to parse a value that is already fully consumed
	// by a grammar, but have remaining 0*n repeated elements.
	// The [1*elem] works while its equivalent 0*elem does not.

	// A minimal reproducibility grammar and input, for debug purposes
	{
		g, err := ParseABNF([]byte("root = foo\r\nfoo  = 1*ALPHA *\"=\"\r\n"))
		require.NoError(t, err)

		const (
			rule  = "root"
			input = "abc"
		)

		path, err := Parse([]byte(input), g, rule)
		assert.NotEmpty(t, path)
		assert.NoError(t, err)
	}

	// The issue's content, for replicability purposes
	{
		g, err := ParseABNF(issue189)
		require.NoError(t, err)

		const (
			rule  = "root"
			input = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Q70dVMtrOQzEFmGOxPAKbNOUSQMISCLhEDfGpMG0WM4"
		)

		path, err := Parse([]byte(input), g, rule)
		assert.NotEmpty(t, path)
		assert.NoError(t, err)
	}
}

func Test_U_ParseCharValMultiByteUTF8(t *testing.T) {
	// Issue #205: ElemCharVal used a byte offset to index a rune slice,
	// so any multi-byte UTF-8 input matched the wrong rune, leading to false negatives.
	g := &Grammar{
		Rulemap: map[string]*Rule{
			"root": {
				Name: "root",
				Alternation: Alternation{
					Concatenations: []Concatenation{
						{
							Repetitions: []Repetition{
								{
									Min: 1, Max: 1,
									Element: ElemCharVal{
										Sensitive: true,
										Values:    []rune{'é', 'a', 'b'},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Matching multi-byte input must return a non-empty path.
	paths, err := Parse([]byte("éab"), g, "root")
	assert.NoError(t, err)
	assert.NotEmpty(t, paths)
}

func Test_U_ParseStackOverflow(t *testing.T) {
	// Left-recursive: previously crashed Parse with fatal stack overflow.
	{
		g, _ := ParseABNF([]byte("s = s \"a\" / \"a\"\r\n"), WithValidation(false))
		paths, err := Parse([]byte("aaaa"), g, "s")
		assert.Empty(t, paths)
		assert.Error(t, err)
	}

	// Sanity: a normal left-terminating grammar still parses fine.
	{
		g, _ := ParseABNF([]byte("s = \"a\" *(\"b\" / \"c\")\r\n"), WithValidation(false))
		paths, err := Parse([]byte("abcbc"), g, "s")
		assert.NotEmpty(t, paths)
		assert.NoError(t, err)
	}

	// Sanity: ParseABNF (uses fixed ABNF grammar) still works.
	{
		_, err := ParseABNF([]byte("greeting = \"hello\" SP \"world\"\r\n"))
		assert.NoError(t, err)
	}
}

// Test_U_IsValid verifies (*Grammar).IsValid, which is now backed by the
// polynomial position-set recognizer (recognize.go) instead of enumerating
// every parse path. The table documents the expected contract:
//   - a left-terminating rule yields a boolean verdict and no error ;
//   - a non-left-terminating rule -- including any left-recursive one, whether
//     direct or indirect, and the empty char-val case of issue #206 -- is
//     refused with an error ;
//   - an unknown rulename is an error.
//
// The "ambiguous-large-input" case is also a regression guard: that input has
// 2^200 distinct parse paths and would never terminate under the previous
// path-enumerating implementation, so its mere completion proves IsValid stays
// polynomial.
func Test_U_IsValid(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Grammar       *Grammar
		Rulename      string
		Input         []byte
		ExpectedValid bool
		ExpectErr     bool
	}{
		"charval-match": {
			Grammar:       mustGrammar("s = \"abc\"\r\n"),
			Rulename:      "s",
			Input:         []byte("abc"),
			ExpectedValid: true,
		},
		"charval-nomatch": {
			Grammar:       mustGrammar("s = \"abc\"\r\n"),
			Rulename:      "s",
			Input:         []byte("abd"),
			ExpectedValid: false,
		},
		"bounded-rep-in-range": {
			Grammar:       mustGrammar("s = 2*4\"a\"\r\n"),
			Rulename:      "s",
			Input:         []byte("aaa"),
			ExpectedValid: true,
		},
		"bounded-rep-too-few": {
			Grammar:       mustGrammar("s = 2*4\"a\"\r\n"),
			Rulename:      "s",
			Input:         []byte("a"),
			ExpectedValid: false,
		},
		"bounded-rep-too-many": {
			Grammar:       mustGrammar("s = 2*4\"a\"\r\n"),
			Rulename:      "s",
			Input:         []byte("aaaaa"),
			ExpectedValid: false,
		},
		"option-present": {
			Grammar:       mustGrammar("s = [\"a\"] \"b\"\r\n"),
			Rulename:      "s",
			Input:         []byte("ab"),
			ExpectedValid: true,
		},
		"option-absent": {
			Grammar:       mustGrammar("s = [\"a\"] \"b\"\r\n"),
			Rulename:      "s",
			Input:         []byte("b"),
			ExpectedValid: true,
		},
		"numval-range-in": {
			Grammar:       mustGrammar("s = %x61-63\r\n"),
			Rulename:      "s",
			Input:         []byte("b"),
			ExpectedValid: true,
		},
		"numval-range-out": {
			Grammar:       mustGrammar("s = %x61-63\r\n"),
			Rulename:      "s",
			Input:         []byte("d"),
			ExpectedValid: false,
		},
		"core-rule": {
			Grammar:       mustGrammar("s = 1*DIGIT\r\n"),
			Rulename:      "s",
			Input:         []byte("0042"),
			ExpectedValid: true,
		},
		"backtracking-needed": {
			// The greedy *"ab" must give a character back so the trailing
			// "a" can match the final byte.
			Grammar:       mustGrammar("s = *\"ab\" \"a\"\r\n"),
			Rulename:      "s",
			Input:         []byte("ababa"),
			ExpectedValid: true,
		},
		"mutual-recursion": {
			Grammar:       mustGrammar("a = \"x\" b\r\nb = \"y\" / \"y\" a\r\n"),
			Rulename:      "a",
			Input:         []byte("xyxy"),
			ExpectedValid: true,
		},
		"ambiguous-correct": {
			Grammar:       mustGrammar("s = *(\"a\" / \"a\")\r\n"),
			Rulename:      "s",
			Input:         []byte("aaaa"),
			ExpectedValid: true,
		},
		"ambiguous-large-input": {
			// 2^200 distinct parse paths: tractable only because IsValid no
			// longer enumerates them. Guards against exponential regression.
			Grammar:       mustGrammar("s = *(\"a\" / \"a\")\r\n"),
			Rulename:      "s",
			Input:         []byte(strings.Repeat("a", 200)),
			ExpectedValid: true,
		},
		"non-left-terminating-empty-charval": {
			// Issue #206: a = *"" is non-left-terminating; IsValid refuses it.
			Grammar:   mustGrammar("a = *\"\"\r\n"),
			Rulename:  "a",
			Input:     []byte("test"),
			ExpectErr: true,
		},
		"direct-left-recursion": {
			Grammar:   mustGrammar("s = s \"a\" / \"a\"\r\n"),
			Rulename:  "s",
			Input:     []byte("aaaa"),
			ExpectErr: true,
		},
		"indirect-left-recursion": {
			Grammar:   mustGrammar("s = t \"a\"\r\nt = s / \"b\"\r\n"),
			Rulename:  "s",
			Input:     []byte("ba"),
			ExpectErr: true,
		},
		"unknown-rule": {
			Grammar:   mustGrammar("s = \"a\"\r\n"),
			Rulename:  "nope",
			Input:     []byte("a"),
			ExpectErr: true,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			valid, err := tt.Grammar.IsValid(tt.Rulename, tt.Input)
			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected error: %t ; got %v", tt.ExpectErr, err)
			}
			if tt.ExpectErr {
				return
			}
			assert.Equal(tt.ExpectedValid, valid)
		})
	}
}

// Test_U_IsValidMatchesParse cross-checks the recognizer-backed IsValid against
// an independent oracle: the path-enumerating Parse, which is complete for
// left-terminating grammars. For every grammar below and every input over a
// small alphabet up to a bounded length, IsValid must return true exactly when
// Parse finds at least one path that consumes the whole input. This is the
// property that makes the recognizer a behaviour-preserving replacement of the
// previous Parse-based IsValid.
func Test_U_IsValidMatchesParse(t *testing.T) {
	t.Parallel()

	var grammars = map[string]struct {
		Grammar  *Grammar
		Rulename string
	}{
		"ambiguous":        {mustGrammar("s = *(\"a\" / \"a\")\r\n"), "s"},
		"overlapping-alts": {mustGrammar("s = 1*(\"a\" / \"ab\")\r\n"), "s"},
		"ambiguous-split":  {mustGrammar("s = *\"a\" *\"a\"\r\n"), "s"},
		"prefix-alts":      {mustGrammar("s = \"a\" / \"ab\" / \"abc\"\r\n"), "s"},
		"bounded-rep":      {mustGrammar("s = 2*4\"a\"\r\n"), "s"},
		"option":           {mustGrammar("s = [\"a\"] \"b\"\r\n"), "s"},
		"group-rep":        {mustGrammar("s = (\"a\" / \"b\") *(\"a\" / \"b\")\r\n"), "s"},
		"numval-range":     {mustGrammar("s = %x61-63 *%x61-63\r\n"), "s"},
		"numval-series":    {mustGrammar("s = %x61.62.63\r\n"), "s"},
		"mutual-recursion": {mustGrammar("a = \"x\" b\r\nb = \"y\" / \"y\" a\r\n"), "a"},
		"core-rules":       {mustGrammar("s = *(ALPHA / DIGIT)\r\n"), "s"},
		"backtracking":     {mustGrammar("s = *\"ab\" \"a\"\r\n"), "s"},
	}

	inputs := allInputsUpTo("abxy1", 5)

	for testname, tt := range grammars {
		t.Run(testname, func(t *testing.T) {
			for _, in := range inputs {
				// Oracle: Parse is complete for left-terminating grammars, so
				// "at least one full-consuming path" is the ground truth.
				paths, err := Parse(in, tt.Grammar, tt.Rulename)
				require.NoError(t, err)
				want := len(paths) != 0

				got, err := tt.Grammar.IsValid(tt.Rulename, in)
				require.NoError(t, err)
				assert.Equalf(t, want, got, "grammar %q input %q", testname, string(in))
			}
		})
	}
}

// allInputsUpTo returns every string over alphabet with length in [0, maxLen],
// as byte slices, for exhaustive differential testing.
func allInputsUpTo(alphabet string, maxLen int) [][]byte {
	out := [][]byte{{}}
	cur := []string{""}
	for l := 1; l <= maxLen; l++ {
		next := make([]string, 0, len(cur)*len(alphabet))
		for _, p := range cur {
			for _, c := range alphabet {
				s := p + string(c)
				next = append(next, s)
				out = append(out, []byte(s))
			}
		}
		cur = next
	}
	return out
}
