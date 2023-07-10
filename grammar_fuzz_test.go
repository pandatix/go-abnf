package goabnf

import "testing"

func FuzzParseABNF(f *testing.F) {
	f.Add(atomicAbnf)
	f.Add(platypusAbnf)
	f.Add(funAbnf)
	f.Add(noobAbnf)
	f.Add(rulelistAbnf)
	f.Add(ruleAbnf)
	f.Add(abnfAbnf)
	f.Add(fixedAbnfAbnf)
	f.Add(fixedAbnfRawAbnf)

	f.Fuzz(func(t *testing.T, input []byte) {
		path, err := ParseABNF(input)

		if err != nil {
			if path != nil {
				t.Fatal("Expected no path when error")
			}
		} else {
			if path == nil {
				t.Fatal("Expected a path when no error")
			}
		}
	})
}
