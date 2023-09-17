package goabnf

// Generate is an experimental feature that consumes a binary
// input as a random source for travelling through the grammar
// resulting in a pseudo-random (reproductible) output.
// It is a good source for testing and fuzzing parsers during
// validation or optimization.
func (g *Grammar) Generate(seed byte, rulename string) []byte {
	// TODO implement *Grammar.Generate
	return nil
}
