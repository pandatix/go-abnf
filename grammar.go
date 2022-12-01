package goabnf

import (
	"errors"
	"fmt"
	"strings"
)

// Grammar represents an ABNF grammar as defined by RFC 5234.
type Grammar struct {
	rulemap map[string]*rule
}

func (g *Grammar) GenerateTests() []byte {
	return nil
}

func (g *Grammar) Validate(value []byte) bool {
	return false
}

// String returns a non pretty-printed string representation
// of the grammar.
func (g *Grammar) String() string {
	str := ""
	for _, rule := range g.rulemap {
		str += rule.String() + "\n"
	}
	return strings.TrimSuffix(str, "\n")
}

// ParseABNF is a helper facilitating the call to Parse using the
// pre-computed ABNF grammar.
func ParseABNF(input []byte) (*Grammar, error) {
	return Parse(input, ABNF, "rulename")
}

// Parse parses an ABNF-compliant input using a grammar.
// It uses uses a top-down parsing strategy using backtracking in
// order to look for solutions. If many are found, it raises an error.
// If the input is invalid (gramatically, incomplete...) it returns
// an error of type *ErrParse.
func Parse(input []byte, grammar *Grammar, rootRulename string) (*Grammar, error) {
	// Select root rule to begin with
	rootRule, ok := grammar.rulemap[rootRulename]
	if !ok {
		return nil, fmt.Errorf("root rule %s not found", rootRulename)
	}

	// Top-down backtracking solution finding process
	solves := parseAlternation(grammar, rootRule.alternation, input, 0)

	// Check solutions
	g := (*Grammar)(nil)
	switch len(solves) {
	case 0:
		return nil, errors.New("invalid ABNF input")

	case 1:
		g = &Grammar{
			rulemap: g.rulemap,
		}

	default:
		return nil, errors.New("multiple ABNF solves found")
	}

	// TODO validate g => all called rules exist

	return g, nil
}

func parseAlternation(grammar *Grammar, alt alternation, input []byte, index int) (solves []*solution) {
	for _, concat := range alt.concatenations {
		// Save index to backtrack on it
		savedIndex := index
		for _, rep := range concat.repetitions {
			// TODO iterate indefinitely until reached max or index == len(index)
			switch v := rep.element.(type) {
			case elemRulename:
				svs := parseAlternation(grammar, getRule(v.name, grammar).alternation, input, index)
				solves = append(solves, svs...)

			case elemGroup:
				svs := parseAlternation(grammar, v.alternation, input, index)
				solves = append(solves, svs...)

			case elemOption:
				svs := parseAlternation(grammar, v.alternation, input, index)
				solves = append(solves, svs...)

				// case elemCharVal:
				// 	svs := parseElemCharVal(grammar, grammar.rulemap[v.name], input, index)
				// 	solves = append(solves, svs...)

				// case elemNumVal:
				// 	svs := parseElemNumVal(grammar, grammar.rulemap[v.name], input, index)
				// 	solves = append(solves, svs...)

				// case elemProseVal:
				// 	svs := parseElemProseVal(grammar, grammar.rulemap[v.name], input, index)
				// 	solves = append(solves, svs...)
			}
		}
		// Restore index for backtracking
		index = savedIndex
	}
	return solves
}

func parseElemGroup(grammar *Grammar, currRule *rule, input []byte, index int) (solves []*solution) {
	return
}

func parseElemOption(grammar *Grammar, currRule *rule, input []byte, index int) (solves []*solution) {
	return
}

func parseElemCharVal(grammar *Grammar, currRule *rule, input []byte, index int) (solves []*solution) {
	return
}

func parseElemNumVal(grammar *Grammar, currRule *rule, input []byte, index int) (solves []*solution) {
	return
}

func parseElemProseVal(grammar *Grammar, currRule *rule, input []byte, index int) (solves []*solution) {
	return
}

type solution struct {
	rulemap map[string]*rule
}

type ErrParse struct{}

func (err ErrParse) Error() string {
	// TODO implement parse error message
	return ""
}

var _ error = (*ErrParse)(nil)

// getRule returns the rule by the given rulename, wether
// it is a core rule or present in the grammar.
func getRule(rulename string, grammar *Grammar) *rule {
	if r, ok := coreRules[rulename]; ok {
		return r
	}
	return grammar.rulemap[rulename]
}

// ABNF is the pre-computed ABNF grammar.
var ABNF = &Grammar{
	rulemap: map[string]*rule{
		abnfRulelist.name:      abnfRulelist,
		abnfRule.name:          abnfRule,
		abnfRulename.name:      abnfRulename,
		abnfDefinedAs.name:     abnfDefinedAs,
		abnfElements.name:      abnfElements,
		abnfCWsp.name:          abnfCWsp,
		abnfCNl.name:           abnfCNl,
		abnfComment.name:       abnfComment,
		abnfAlternation.name:   abnfAlternation,
		abnfConcatenation.name: abnfConcatenation,
		abnfRepetition.name:    abnfRepetition,
		abnfRepeat.name:        abnfRepeat,
		abnfElement.name:       abnfElement,
		abnfGroup.name:         abnfGroup,
		abnfOption.name:        abnfOption,
		abnfCharVal.name:       abnfCharVal,
		abnfNumVal.name:        abnfNumVal,
		abnfBinVal.name:        abnfBinVal,
		abnfDecVal.name:        abnfDecVal,
		abnfHexVal.name:        abnfHexVal,
		abnfProseVal.name:      abnfProseVal,
	},
}
