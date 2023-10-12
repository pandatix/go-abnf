package goabnf_test

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

func FuzzGenerate(f *testing.F) {
	for _, tt := range testsGenerate {
		f.Add(tt.Seed, tt.Rulename)
	}

	f.Fuzz(func(t *testing.T, seed int64, rulename string) {
		out, err := goabnf.ABNF.Generate(seed, rulename, goabnf.WithRepMax(16), goabnf.WithThreshold(1024))
		if err != nil {
			if len(out) != 0 {
				t.Fatal("output should be empty in case of an error")
			}
			return
		}

		valid, err := goabnf.ABNF.IsValid(rulename, out)
		if err != nil || !valid {
			t.Fatalf("generated output is invalid, out: %s", out)
		}
	})
}
