package goabnf

import (
	_ "embed"
	"testing"
)

func FuzzGenerate(f *testing.F) {
	for _, tt := range testsGenerate {
		f.Add(tt.Seed, tt.Rulename)
	}

	f.Fuzz(func(t *testing.T, seed int64, rulename string) {
		out, err := ABNF.Generate(seed, rulename, WithRepMax(16), WithThreshold(1024))
		if err != nil {
			if len(out) != 0 {
				t.Fatal("output should be empty in case of an error")
			}
			return
		}

		valid, err := ABNF.IsValid(rulename, out)
		if err != nil || !valid {
			t.Fatalf("generated output is invalid, out: %s", out)
		}
	})
}
