package goabnf

import (
	"fmt"
	"strings"
)

// Grammar represents an ABNF grammar as defined by RFC 5234.
// It is constituted of a set of rules with an unique name.
type Grammar struct {
	rulemap map[string]*rule
}

// GenerateTests is an experimental feature that consumes a binary
// input as a random source for travelling through the grammar
// resulting in a pseudo-random (reproductible) output.
// It is a good source for testing and fuzzing parsers during
// validation or optimization.
func (g *Grammar) GenerateTest(source []byte) []byte {
	// XXX implement the *Grammar.GenerateTest method
	return nil
}

// Validate checks there exist only one path that completly consumes
// value, hence is valide given this grammar.
// Notice it validates uniqueness of value as having multiple valid
// paths may lead to inconsistencies between implementations, thus
// leading to interpretations, bugs and maybe vulnerabilities.
func (g *Grammar) Validate(value []byte) bool {
	return false
}

// String returns string representation of the grammar.
// TODO implement PrettyPrint
func (g *Grammar) String() string {
	str := ""
	for _, rule := range g.rulemap {
		str += rule.String() + "\n"
	}
	return strings.TrimSuffix(str, "\n")
}

// GST, or Grammar Syntax Tree, represents the ouput of a parsing.
// This should be lexed in order to be usable as a grammar source.
type GST Segment

// Segment represents a portion of an input that matched a rule from
// an index to another, with a composite structure.
//
// Notice it does not matches specifically ABNF grammar, but any
// grammar compatible. The most common case is parsing an input with
// the ABNF grammar as source, which is then lexed to fall back into
// a ready-to-go ABNF definition of this input.
// There may exist specific cases where you want to use another grammar
// as source (e.g. EBNF grammar provided by parsing EBNF specification
// input written in ABNF with the ABNF grammar as source, which as
// itself been implemented from the ABNF specification of ABNF in the
// ABNF structure).
//
// This imply that you may not deal with a parsed ABNF straightly, but
// with the ABNF representation of your input in ABNF structure using
// the grammar ruleset.
// This is like a complex game, but without the fun and friends.
//
// For instance, let's take the input `a = "b"“ with the ABNF grammar
// as source, i.e. a rule `a` that matches the string "b".
// A root segment (GST) is created with Start=0 and MatchRule=rulelist,
// as is constitutes the root rule of an ABNF grammar.
// Then rulelist is a single alternation, creating a single sub segment.
// The process then goes with this segment with Start=0.
// This alternation is composed of a single concatenation, so the same
// goes on.
// This concatenation is composed of a single repetition with min=1
// and no maximum, composed of a group.
// This group is composed of an alternation that is itself composed by
// two concatenations.
// The first concatenation is composed of a single repetition with
// min=1 and max=1 that is composed of the rule "rule".
// The process then backtrack to this rule, getting back a list of valid
// segments to follow.
// The second concatenation is composed of a single repetition with
// min=1 and max=1 is composed of a group.
// This group is composed of an alternation, itself composed of a single
// concatenation itself composed of two repetitions.
// The first has a min=0 and no max. The process then backtracks to the
// rule "WSP".
// The second has a min=1 and max=1. The process then backtracks to the
// rule "c-nl".
// Finally, everything backtracks and the segment is composed.
//
// When the process backtracks, it needs to "fork".
// TODO fork
//
// TODO Then, we need to lex this GST to obtain a grammar.
//
// In the end, we have a rule "a" that matches the single string "b".
type Segment struct {
	// Sub segments aka children
	Sub []*Segment
	// MatchRule in source's grammar ruleset
	MatchRule string
	// Start ≤ End
	Start, End int
}

// ParseABNF is a helper facilitating the call to Parse using the
// pre-computed ABNF grammar and evaluates the resulting grammar
// so the returned one is ready for parsing.
func ParseABNF(input []byte) (*GST, error) {
	g, err := Parse(input, ABNF, "rulelist")
	if err != nil {
		return nil, err
	}
	// TODO evaluate grammar
	return g, nil
}

// Parse parses an ABNF-compliant input using a grammar.
// It uses uses a top-down parsing strategy using backtracking in
// order to look for solutions. If many are found, it raises an error.
// If the input is invalid (gramatically, incomplete...) it returns
// an error of type *ErrParse.
func Parse(input []byte, grammar *Grammar, rootRulename string) (*GST, error) {
	// Select root rule to begin with
	rootRule, ok := grammar.rulemap[rootRulename]
	if !ok {
		return nil, fmt.Errorf("root rule %s not found", rootRulename)
	}

	// Parse input with grammar's root rule
	root := &Segment{
		Sub:       []*Segment{},
		MatchRule: rootRulename,
		Start:     0,
		End:       0, // Set later
	}
	index := 0
	solveAlt(grammar, rootRule.alternation, root, input, &index)
	root.End = index // should be len(input)

	// TODO Check solutions

	// TODO validate g => all called rules exist

	return nil, nil
}

func solveAlt(grammar *Grammar, alt alternation, seg *Segment, input []byte, index *int) {
	for _, concat := range alt.concatenations {
		for _, rep := range concat.repetitions {
			solveRep(grammar, rep, seg, input, index)
		}
	}
	seg.End = *index
}

func solveRep(grammar *Grammar, rep repetition, seg *Segment, input []byte, index *int) {
	// Add to possibles iif y >= rep.min
	// possibles := []*Segment{}

	// TODO "fork" is min=0 as long as it is optional
	y := 0
	end := endRep(rep, input, *index, y)
	for end {
		// TODO handle minimum iterations
		// TODO "fork"

		switch v := rep.element.(type) {
		case elemRulename:
			// Create sub segment
			sub := &Segment{
				Sub:       []*Segment{},
				MatchRule: v.name,
				Start:     *index,
				End:       0, // Set later
			}
			// Set it has part of children's current one
			seg.Sub = append(seg.Sub, sub)
			// Propagate to rule
			solveAlt(grammar, getRule(v.name, grammar).alternation, sub, input, index)
			// Set end index for others repetitions and upper
			seg.End = *index

		case elemOption:
			solveRep(grammar, repetition{
				min:     0,
				max:     1,
				element: v.alternation,
			}, seg, input, index)

		case elemGroup:
			solveAlt(grammar, v.alternation, seg, input, index)

		case elemNumVal:
			switch v.status {
			case statRange:
				min, max := atob(v.elems[0], v.base), atob(v.elems[1], v.base)
				if min <= input[*index] && input[*index] <= max {
					*index++
				} else {
					// TODO drop "fork"
					fmt.Printf("did not match\n")
					return
				}

			case statSeries:
				for _, elem := range v.elems {
					if atob(elem, v.base) == input[*index] {
						*index++
					} else {
						// TODO drop "fork"
						fmt.Printf("did not match\n")
						return
					}
				}
			}

		case elemProseVal:
			fmt.Printf("elemProseVal\n")
			// "<" ... ">"
			// -> first char MUST be "<"
			// -> last char MUST be ">"

		case elemCharVal:
			fmt.Printf("elemCharVal\n")
			for _, val := range v.values {
				if sensequal(val, input[*index], v.sensitive) {
					*index++
				} else {
					// TODO drop "fork"
					fmt.Printf("did not match\n")
					return
				}
			}
		}

		y++
		end = endRep(rep, input, *index, y)
	}
}

// atob converts str to byte given the base.
func atob(str, base string) byte {
	switch base {
	case "b":
		return bintob(str)
	case "d":
		return dectob(str)
	case "x":
		return hextob(str)
	}
	panic("invalid base")
}

func bintob(str string) byte {
	// XXX Length can't be more than 64 bits
	out := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		cv := 0
		switch c {
		case '0':
			cv = 0
		case '1':
			cv = 1
		default:
			panic("invalid bit: " + string(c))
		}
		out += cv * pow(2, len(str)-i-1)
	}
	return byte(out)
}

func dectob(str string) byte {
	out := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		cv := 0
		switch c {
		case '0':
			cv = 0
		case '1':
			cv = 1
		case '2':
			cv = 2
		case '3':
			cv = 3
		case '4':
			cv = 4
		case '5':
			cv = 5
		case '6':
			cv = 6
		case '7':
			cv = 7
		case '8':
			cv = 8
		case '9':
			cv = 9
		default:
			panic("invalid dec: " + string(c))
		}
		out += cv * pow(10, len(str)-i-1)
	}
	return byte(out)
}

func hextob(str string) byte {
	out := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		cv := 0
		switch c {
		case '0':
			cv = 0
		case '1':
			cv = 1
		case '2':
			cv = 2
		case '3':
			cv = 3
		case '4':
			cv = 4
		case '5':
			cv = 5
		case '6':
			cv = 6
		case '7':
			cv = 7
		case '8':
			cv = 8
		case '9':
			cv = 9
		case 'A', 'a':
			cv = 10
		case 'B', 'b':
			cv = 11
		case 'C', 'c':
			cv = 12
		case 'D', 'd':
			cv = 13
		case 'E', 'e':
			cv = 14
		case 'F', 'f':
			cv = 15
		default:
			panic("invalid hex: " + string(c))
		}
		out += cv * pow(16, len(str)-i-1)
	}
	return byte(out)
}

func pow(v, e int) int {
	if e == 0 {
		return 1
	}
	for i := 1; i < e; i++ {
		v *= v
	}
	return v
}

func sensequal(target, actual byte, sensitive bool) bool {
	if !sensitive {
		return target == actual
	}
	if target == actual { // if sensitive but strictly equal, fast return
		return true
	}
	target, actual = strmin(target), strmin(actual)
	return target == actual
}

func strmin(r byte) byte {
	if r >= 'A' || r <= 'Z' {
		return r - 'A' + 'a'
	}
	return r
}

// endRep returns true if a new repetition should be tested or not.
// If the repetition has no max, it returns whether input has been
// totally consumed.
// Else, it checks if input has been totally consumed AND if there
// could be other repetitions.
func endRep(rep repetition, input []byte, index, y int) bool {
	if rep.max == inf {
		return index < len(input)
	}
	return index < len(input) && y < rep.max
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
