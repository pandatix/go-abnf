package goabnf

import (
	"math/rand"
	"slices"
	"testing"
)

// The defining invariant of the generator: every production it emits, from any
// entropy source, is accepted by the grammar. This is what makes it safe to put
// in front of a fuzzing engine.
func Test_U_Generator_AlwaysValid(t *testing.T) {
	t.Parallel()
	cases := []struct{ src, rule string }{
		{`a = "a" / "b"`, "a"},
		{`a = *"a"`, "a"},
		{`a = 1*DIGIT`, "a"},
		{`a = *("a" / "b")`, "a"},
		{`a = 1*2("a" / "b")`, "a"},
		{`a = "a" ["b"] "c"`, "a"},
		{`a = 2"ab" %x20 "z"`, "a"},
		{`a = ALPHA *(ALPHA / DIGIT)`, "a"},
		{`a = %x61-63`, "a"},
		{"a = b c\r\nb = \"x\"\r\nc = 1*3\"y\"", "a"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.src, func(t *testing.T) {
			t.Parallel()
			g, err := ParseABNF([]byte(c.src + "\r\n"))
			if err != nil {
				t.Fatalf("ParseABNF: %v", err)
			}
			tg, err := g.TransitionGraph(c.rule, WithDeflateRules(true), WithMaxNodes(1<<16))
			if err != nil {
				t.Fatalf("TransitionGraph: %v", err)
			}
			gen, err := NewGenerator(tg, WithMaxLength(64), WithMaxReps(8))
			if err != nil {
				t.Fatalf("NewGenerator: %v", err)
			}

			// Empty tape is total and valid.
			if ok, _ := g.IsValid(c.rule, gen.Generate(nil)); !ok {
				t.Fatalf("empty tape produced an invalid production")
			}
			r := rand.New(rand.NewSource(1))
			for range 3000 {
				tape := make([]byte, r.Intn(40))
				r.Read(tape)
				prod := gen.Generate(tape)
				if ok, err := g.IsValid(c.rule, prod); err != nil || !ok {
					t.Fatalf("invalid production %q (ok=%v err=%v)", prod, ok, err)
				}
				// Determinism: identical tape, identical output.
				if string(gen.Generate(tape)) != string(prod) {
					t.Fatalf("non-deterministic output for tape %q", tape)
				}
			}
			for range 1000 {
				if ok, _ := g.IsValid(c.rule, gen.GenerateRand(r)); !ok {
					t.Fatalf("invalid production from rand source")
				}
			}
		})
	}
}

// ExpectedNext (graph frontier) and IsValid (recognizer) are independent
// engines; they must agree. We assert three ties between them on generated data:
//
//	(a) along any valid production P, the actual next byte is always in the
//	    expected set, and P itself is reported as accepted;
//	(b) accepts(P) == IsValid(P);
//	(c) a byte the frontier forbids really does make the string invalid
//	    (P[:k]+b with b not expected => IsValid false).
func Test_U_ExpectedNext_AgreesWithRecognizer(t *testing.T) {
	t.Parallel()
	cases := []struct{ src, rule string }{
		{`a = "a" / "b"`, "a"},
		{`a = *"a"`, "a"},
		{`a = 1*DIGIT`, "a"},
		{`a = *("a" / "b")`, "a"},
		{`a = "a" ["b"] "c"`, "a"},
		{`a = "a" ("b" / "c")`, "a"},
		{`a = %x61-63`, "a"},
		{`a = ALPHA *(ALPHA / DIGIT)`, "a"},
		{"quad = f \".\" f \".\" f \".\" f\r\nf = 1*3DIGIT", "quad"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.src, func(t *testing.T) {
			t.Parallel()
			g, err := ParseABNF([]byte(c.src + "\r\n"))
			if err != nil {
				t.Fatalf("ParseABNF: %v", err)
			}
			tg, err := g.TransitionGraph(c.rule, WithDeflateRules(true), WithMaxNodes(1<<16))
			if err != nil {
				t.Fatalf("TransitionGraph: %v", err)
			}
			gen, err := NewGenerator(tg, WithMaxLength(48), WithMaxReps(6))
			if err != nil {
				t.Fatalf("NewGenerator: %v", err)
			}
			r := rand.New(rand.NewSource(2))
			for range 1500 {
				tape := make([]byte, r.Intn(40))
				r.Read(tape)
				P := gen.Generate(tape)

				// (a)+(b): P is valid, so it must be accepted, and every prefix's
				// actual continuation byte must be in the expected set.
				if nx, accepts, ok := gen.ExpectedNext(P); ok {
					if !accepts {
						t.Fatalf("ExpectedNext(%q).accepts=false but it is a valid production", P)
					}
					_ = nx
				}
				for k := range P {
					nx, accepts, ok := gen.ExpectedNext(P[:k])
					if !ok {
						continue
					}
					if v, _ := g.IsValid(c.rule, P[:k]); v != accepts {
						t.Fatalf("accepts(%q)=%v but IsValid=%v", P[:k], accepts, v)
					}
					inExpected := slices.Contains(nx, P[k])
					if !inExpected {
						t.Fatalf("actual next byte %q not in ExpectedNext(%q)=%q", P[k], P[:k], string(nx))
					}
					// (c): a forbidden byte must yield an invalid string.
					allowed := map[byte]bool{}
					for _, b := range nx {
						allowed[b] = true
					}
					for cand := range 256 {
						if !allowed[byte(cand)] {
							bad := append(append([]byte{}, P[:k]...), byte(cand))
							if v, _ := g.IsValid(c.rule, bad); v {
								t.Fatalf("byte %#x forbidden by ExpectedNext at %q but IsValid(%q)=true", cand, P[:k], bad)
							}
							break
						}
					}
				}
			}
		})
	}
}
