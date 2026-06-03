package example

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

//go:embed my-grammar.abnf
var myGrammar []byte

// A seed int gives the coverage engine almost no gradient (mutating the int
// jumps randomly around production space), and it only ever produces valid
// inputs. Kept as a baseline to contrast with the tape-driven targets.
func FuzzFunction(f *testing.F) {
	g, err := goabnf.ParseABNF(myGrammar)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		b, _ := g.Generate(seed, "a",
			goabnf.WithRepMax(15),
			goabnf.WithThreshold(1024),
		)
		Function(b)
	})
}

// Every tape maps to a grammar-valid production, so the engine's byte mutations
// explore the grammar instead of bouncing off the target's first syntax check,
// and deep target code is always reached. Oracle: a correct target must ACCEPT
// every valid production -> finds FALSE REJECTIONS.
func FuzzValidAccepted(f *testing.F) {
	g, gen := newGen(f)
	for _, seed := range [][]byte{nil, {0}, {1, 2, 3}, {255, 7, 42, 9}, {5, 5, 5, 5, 5}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tape []byte) {
		prod := gen.Generate(tape)
		// Self-check: a failure here is a go-abnf generator bug, not a target bug.
		if ok, _ := g.IsValid("a", prod); !ok {
			t.Fatalf("generator emitted a grammar-invalid production: %q", prod)
		}
		if !Function(prod) {
			t.Fatalf("target REJECTED a valid production (false rejection): %q", prod)
		}
	})
}

// Same, but WithStableAddressing(): for concatenation/fixed-repetition-dominated
// grammars this gives a smoother gradient (a one-byte tape edit perturbs one
// decision instead of reframing all later ones). It can hurt repetition-heavy
// grammars, so treat it as an opt-in to A/B against the default codec.
func FuzzValidAcceptedStable(f *testing.F) {
	g, err := goabnf.ParseABNF(myGrammar)
	if err != nil {
		f.Fatal(err)
	}
	tg, err := g.TransitionGraph("a",
		goabnf.WithDeflateRules(true),
		goabnf.WithMaxNodes(1<<20),
	)
	if err != nil {
		f.Fatal(err)
	}
	gen, err := goabnf.NewGenerator(tg,
		goabnf.WithMaxLength(32),
		goabnf.WithMaxReps(8),
		goabnf.WithStableAddressing(),
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, tape []byte) {
		if prod := gen.Generate(tape); !Function(prod) {
			t.Fatalf("target rejected a valid production: %q", prod)
		}
	})
}

// Minimal off-grammar perturbations of a valid production, each verified to be
// genuinely rejected by the grammar and carrying a label. They reach the error
// paths a valid-only generator can never hit. Oracle: a correct target must
// REJECT every near-miss -> finds OVER-ACCEPTANCE (a parser swallowing
// malformed input — the security-relevant direction).
func FuzzNearMissRejected(f *testing.F) {
	g, gen := newGen(f)
	for _, seed := range [][]byte{nil, {0}, {1, 2}, {9, 9, 9}, {3, 1, 4, 1}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tape []byte) {
		nm, label, ok := gen.NearMiss(tape)
		if !ok {
			return // no near-miss for this tape; nothing to assert
		}
		// Sanity: the near-miss really is outside the grammar.
		if v, _ := g.IsValid("a", nm); v {
			t.Fatalf("near-miss unexpectedly valid: %q", nm)
		}
		if Function(nm) {
			t.Fatalf("target ACCEPTED an invalid input (over-acceptance): %q (%s)", nm, label)
		}
	})
}

// ExpectedNext gives the octets the grammar allows after a prefix. Appending one
// it forbids yields a guaranteed-invalid input whose first error sits at a KNOWN
// offset. A correct target must reject it; if your target reports an error
// position, assert it points at that offset (see the commented line).
func FuzzExpectedNextErrorPosition(f *testing.F) {
	_, gen := newGen(f)
	f.Add([]byte{2, 4, 6, 8})
	f.Fuzz(func(t *testing.T, tape []byte) {
		prod := gen.Generate(tape)
		off := 0
		if len(prod) > 0 && len(tape) > 0 {
			off = int(tape[0]) % (len(prod) + 1)
		}
		nx, _, ok := gen.ExpectedNext(prod[:off])
		if !ok {
			return
		}
		allowed := map[byte]bool{}
		for _, b := range nx {
			allowed[b] = true
		}
		var bad byte
		found := false
		for c := range 256 {
			if !allowed[byte(c)] {
				bad, found = byte(c), true
				break
			}
		}
		if !found {
			return
		}
		// Valid prefix + an octet the grammar cannot accept there => invalid,
		// with the violation at exactly offset `off`.
		input := append(append([]byte{}, prod[:off]...), bad)
		if Function(input) {
			t.Fatalf("target accepted an illegal octet 0x%02x at offset %d (expected one of %q): %q",
				bad, off, string(nx), input)
		}
		// If your target exposes an error offset, e.g. `_, pos := FunctionAt(input)`:
		//   if pos != off { t.Fatalf("error reported at %d, want %d for %q", pos, off, input) }
	})
}

// One tape exercises the whole equivalence: the target must ACCEPT the valid
// production AND REJECT the near-miss derived from the same entropy. Catches
// false rejections and over-acceptance together, maximizing signal per exec.
func FuzzDifferentialBothDirections(f *testing.F) {
	g, gen := newGen(f)
	for _, seed := range [][]byte{nil, {1}, {7, 7, 7}, {1, 2, 3, 4, 5}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tape []byte) {
		// Positive direction: valid production must be accepted.
		prod := gen.Generate(tape)
		if ok, _ := g.IsValid("a", prod); ok && !Function(prod) {
			t.Fatalf("false rejection: target rejected valid %q", prod)
		}
		// Negative direction: near-miss from the same tape must be rejected.
		if nm, label, ok := gen.NearMiss(tape); ok {
			if v, _ := g.IsValid("a", nm); !v && Function(nm) {
				t.Fatalf("over-acceptance: target accepted invalid %q (%s)", nm, label)
			}
		}
	})
}

// newGen builds the fully-expanded automaton and a generator for rule "a".
// Shared by the structure-aware targets below.
func newGen(tb testing.TB) (*goabnf.Grammar, *goabnf.Generator) {
	tb.Helper()
	g, err := goabnf.ParseABNF(myGrammar)
	if err != nil {
		tb.Fatal(err)
	}
	tg, err := g.TransitionGraph("a",
		goabnf.WithDeflateRules(true), // expand sub-rules into leaf nodes
		goabnf.WithMaxNodes(1<<20),    // bound construction if the grammar is untrusted
	)
	if err != nil {
		tb.Fatal(err)
	}
	gen, err := goabnf.NewGenerator(tg, goabnf.WithMaxLength(32), goabnf.WithMaxReps(8))
	if err != nil {
		tb.Fatal(err)
	}
	return g, gen
}
