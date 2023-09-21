package goabnf_test

import (
	_ "embed"
	"encoding/json"
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
		} else {
			valid := goabnf.ABNF.IsValid(rulename, out)
			if !valid {
				t.Fatalf("generated output is invalid, out: %s", out)
			}
		}
	})
}

//go:embed testdata/json.abnf
var jsonAbnf []byte

func FuzzGenerateJSON(f *testing.F) {
	g, err := goabnf.ParseABNF(jsonAbnf)
	if err != nil {
		f.Fatalf("invalid grammar: %s", err)
	}

	f.Fuzz(func(t *testing.T, seed int64) {
		// Don't start by the JSON-text grammar as it could generate
		// invalid JSON.
		out, _ := g.Generate(seed, "object")
		t.Logf("generated input %s / %v", out, out)

		var dst any
		if err := json.Unmarshal(out, dst); err != nil {
			t.Fatalf("json is not compliant to ABNF grammar")
		}
	})
}
