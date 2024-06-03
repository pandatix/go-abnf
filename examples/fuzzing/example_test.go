package example

import (
	_ "embed"
	"testing"

	goabnf "github.com/pandatix/go-abnf"
)

//go:embed my-grammar.abnf
var myGrammar []byte

func FuzzFunction(f *testing.F) {
	g, err := goabnf.ParseABNF(myGrammar)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, seed int64) {
		// Generate a random test case based on the seed
		b, _ := g.Generate(seed, "a",
			goabnf.WithRepMax(15),      // Limit repetitions to 15
			goabnf.WithThreshold(1024), // Stop ASAP input generation if reached 1024 bytes
		)

		Function(b)
	})
}
