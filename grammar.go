package goabnf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Grammar represents an ABNF grammar as defined by RFC 5234.
// It is constituted of a set of rules with an unique name.
type Grammar struct {
	rulemap map[string]*rule
}

// IsValid checks there exist at least a path that completly consumes
// input, hence is valide given this gramma and especially one of its
// rule.
func (g *Grammar) IsValid(rulename string, input []byte) bool {
	paths, err := Parse(input, g, rulename)
	return len(paths) != 0 && err == nil
}

// String returns the representation of the grammar that is valid
// according to the ABNF specifications/RFCs.
// This notably imply the use of CRLF instead of LF, and does not
// preserve the initial order nor pretty print it.
func (g *Grammar) String() string {
	str := ""
	for _, rule := range g.rulemap {
		str += rule.String() + "\r\n"
	}
	return str
}

// PrettyPrint returns a prettified string that represents the grammar.
func (g *Grammar) PrettyPrint() string {
	// Determine maximum rulename length
	rulenameLength := 0
	for rulename := range g.rulemap {
		if len(rulename) > rulenameLength {
			rulenameLength = len(rulename)
		}
	}

	// Construct output
	out := ""
	for rulename, rl := range g.rulemap {
		spaces := ""
		for i := 0; i < rulenameLength-len(rulename); i++ {
			spaces += " "
		}

		out += fmt.Sprintf("%s%s = %s\r\n", rulename, spaces, rl.alternation)
	}
	return out
}

// Path represents a portion of an input that matched a rule from
// an index to another, with a composite structure.
//
// Notice it does not matches specifically ABNF grammar, but any
// compatible grammar. The most common case is parsing an input with
// the ABNF grammar as source, which is then lexed to fall back into
// a ready-to-go ABNF grammar of this input.
// There may exist specific cases where you want to use another grammar
// as source (e.g. EBNF grammar provided by parsing EBNF specification
// input written in ABNF with the ABNF grammar as source, which as
// itself been implemented from the ABNF specification of ABNF in the
// ABNF structure).
// For those cases, you can use this implementation as it uses a
// generic behavior, by parsing your source ABNF grammar first then
// use it to validate inputs.
type Path struct {
	// Subpaths aka children. Ordering applies
	Subpaths []*Path
	// MatchRule in source's grammar ruleset
	MatchRule string
	// Start ≤ End
	Start, End int
}

// ParseABNF is a helper facilitating the call to Parse using the
// pre-computed ABNF grammar and lex the resulting to produce a
// ready-to-use grammar.
func ParseABNF(input []byte, opts ...ParseABNFOption) (*Grammar, error) {
	// Process functional options
	o := &options{
		validate: true,
	}
	for _, opt := range opts {
		opt.apply(o)
	}

	// Parse input with ABNF grammar
	paths, err := Parse(input, ABNF, "rulelist")
	if err != nil {
		return nil, err
	}
	path := (*Path)(nil)
	switch len(paths) {
	case 0:
		return nil, errors.New("no solution found, input ABNF grammar may be invalid")
	case 1:
		path = paths[0]
	default:
		return nil, errors.New("multiple solutions found, this should not happen. Please open an issue. This could eventually need an Erratum from IETF tracking")
	}

	// Lex path
	g, err := LexABNF(input, path)
	if err != nil {
		return nil, err
	}

	// Validate semantics
	if o.validate {
		if err := SemvalABNF(g); err != nil {
			return nil, err
		}
	}

	return g, nil
}

// Parse parses an ABNF-compliant input using a grammar.
// It uses uses a top-down parsing strategy using backtracking in
// order to look for solutions. If many are found, it raises an error.
// If the input is invalid (gramatically, incomplete...) it returns
// an error of type *ErrParse.
func Parse(input []byte, grammar *Grammar, rootRulename string) ([]*Path, error) {
	// Select root rule to begin with
	rootRule := getRule(rootRulename, grammar.rulemap)
	if rootRule == nil {
		return nil, fmt.Errorf("root rule %s not found", rootRulename)
	}

	// Parse input with grammar's initial rule
	possibilites := solveAlt(grammar, rootRule.alternation, input, 0)

	// Look for solutions that consumed the whole input
	outPoss := []*Path{}
	for _, poss := range possibilites {
		if poss.End == len(input) {
			pth := poss.Subpaths[0]
			pth.MatchRule = rootRulename
			outPoss = append(outPoss, pth)
		}
	}

	return outPoss, nil
}

func solveAlt(grammar *Grammar, alt alternation, input []byte, index int) []*Path {
	altPossibilities := []*Path{}

	for _, concat := range alt.concatenations {
		cntPossibilities := []*Path{}

		// Init with first repetition (guarantee of at least 1 repetition)
		possibilities := solveRep(grammar, concat.repetitions[0], input, index)
		for _, poss := range possibilities {
			cntPossibilities = append(cntPossibilities, &Path{
				Subpaths:  []*Path{poss},
				MatchRule: "",
				Start:     index,
				End:       poss.End,
			})
		}

		// Keep going and multiply previous paths with current repetition
		// resulting paths
		for i := 1; i < len(concat.repetitions); i++ {
			rep := concat.repetitions[i]

			tmpPossibilities := []*Path{}
			for _, cntPoss := range cntPossibilities {
				possibilities := solveRep(grammar, rep, input, cntPoss.End)
				for _, poss := range possibilities {
					// If the possibility is the empty path, don't append the empty one
					if poss.Start == poss.End {
						tmpPossibilities = append(tmpPossibilities, cntPoss)
						continue
					}

					// Remove empty traversal previous subpath if necessary
					subs := make([]*Path, len(cntPoss.Subpaths))
					copy(subs, cntPoss.Subpaths)
					lastSub := subs[len(subs)-1]
					if lastSub.Start == lastSub.End {
						subs = subs[:len(subs)-1]
					}

					tmpPossibilities = append(tmpPossibilities, &Path{
						Subpaths:  append(subs, poss),
						MatchRule: "",
						Start:     index,
						End:       poss.End,
					})
				}
			}
			cntPossibilities = tmpPossibilities
		}

		altPossibilities = append(altPossibilities, cntPossibilities...)
	}
	return altPossibilities
}

func solveRep(grammar *Grammar, rep repetition, input []byte, index int) []*Path {
	// Fast check won't be out of bounds with first read
	if !solveKeepGoing(rep, input, index, 0) {
		return []*Path{}
	}

	// Find first repetition paths.
	paths := solveElem(grammar, rep.element, input, index)
	pindex := 0

	y := 1
	kg := solveKeepGoing(rep, input, index, y)

	for kg {
		iterPaths := []*Path{}
		for _, poss := range paths[pindex:] {
			elemPossibilities := solveElem(grammar, rep.element, input, poss.End)
			for _, elemPoss := range elemPossibilities {
				ipsubs := make([]*Path, len(poss.Subpaths), len(poss.Subpaths)+1)
				copy(ipsubs, poss.Subpaths)
				ipsubs = append(ipsubs, elemPoss)

				iterPaths = append(iterPaths, &Path{
					Subpaths:  ipsubs,
					MatchRule: "",
					Start:     poss.Start,
					End:       elemPoss.End,
				})
			}
		}

		// Prepare for next iteration
		y++
		kg = solveKeepGoing(rep, input, index, y)

		// If no solutions now, there won't be any later.
		if len(iterPaths) == 0 {
			break
		}
		// If there exist solutions in the given interval, keep them
		// for future iterations.
		if y >= rep.min {
			pindex += len(paths) - pindex
			paths = append(paths, iterPaths...)
		}
	}

	// Add empty solution if is a valid path
	if rep.min == 0 {
		paths = append(paths, &Path{
			Subpaths: []*Path{
				{
					Subpaths:  nil,
					MatchRule: "",
					Start:     index,
					End:       index,
				},
			},
			MatchRule: "", // This will be modified by upper function
			Start:     index,
			End:       index,
		})
	}

	return paths
}

func solveElem(grammar *Grammar, elem elemItf, input []byte, index int) []*Path {
	paths := []*Path{}

	switch v := elem.(type) {
	case elemRulename:
		rule := getRule(v.name, grammar.rulemap)
		possibilities := solveAlt(grammar, rule.alternation, input, index)
		for _, poss := range possibilities {
			poss.MatchRule = v.name
			paths = append(paths, poss)
		}

	case elemOption:
		paths = solveRep(grammar, repetition{
			min:     0,
			max:     1,
			element: elemGroup(v),
		}, input, index)

	case elemGroup:
		paths = solveAlt(grammar, v.alternation, input, index)

	case elemNumVal:
		switch v.status {
		case statRange:
			// Any matches
			min, max := atob(v.elems[0], v.base), atob(v.elems[1], v.base)
			if min <= input[index] && input[index] <= max {
				paths = append(paths, &Path{
					Subpaths:  nil,
					MatchRule: "",
					Start:     index,
					End:       index + 1,
				})
			}

		case statSeries:
			// Only match if all matches in order
			initialIndex := index
			matches := true
			for i := 0; i < len(v.elems) && matches; i++ {
				if atob(v.elems[i], v.base) != input[index] {
					matches = false
				}
				index++
			}
			if matches {
				paths = append(paths, &Path{
					Subpaths:  nil,
					MatchRule: "",
					Start:     initialIndex,
					End:       index,
				})
			}
		}

	case elemProseVal:
		panic("elemProseVal")

	case elemCharVal:
		initialIndex := index
		matches := true
		for i := 0; i < len(v.values) && matches; i++ {
			if sensequal(v.values[i], input[index], v.sensitive) {
				index++
			} else {
				matches = false
			}
		}
		if matches {
			paths = append(paths, &Path{
				Subpaths:  nil,
				MatchRule: "",
				Start:     initialIndex,
				End:       index,
			})
		}
	}
	return paths
}

func sensequal(target, actual byte, sensitive bool) bool {
	if !sensitive {
		target, actual = strmin(target), strmin(actual)
	}
	return target == actual
}

func strmin(r byte) byte {
	if r >= 'A' && r <= 'Z' {
		return r - 'A' + 'a'
	}
	return r
}

// solveKeepGoing returns true if a new repetition should be tested or not.
// If the repetition has no max, it returns whether input has been
// totally consumed.
// Else, it checks if input has been totally consumed AND if there
// could be other repetitions.
func solveKeepGoing(rep repetition, input []byte, index, y int) bool {
	// Find if could handle the length of this repetition
	// considering its type
	couldHandle := true
	switch v := rep.element.(type) {
	case elemNumVal:
		// Check only one byte
		couldHandle = index < len(input)

	case elemCharVal:
		// Check current index+length of char value string is not longer than the input
		couldHandle = index+len(v.values)-1 < len(input)

	case elemProseVal:
		panic("elemProseVal")
	}

	// If no maximum repetition, only bound to input length thus
	// if it could handle its consumption given repetition's type
	if rep.max == inf {
		return couldHandle
	}
	// If has a maximum repetition, check could handle AND will remain
	// under boundary.
	return couldHandle && y < rep.max
}

// LexABNF is the lexer for the ABNF structural model implemented.
func LexABNF(input []byte, path *Path) (*Grammar, error) {
	gr, err := lexABNF(input, path)
	if err != nil {
		return nil, err
	}
	return gr.(*Grammar), nil
}

func lexABNF(input []byte, path *Path) (any, error) {
	switch path.MatchRule {
	case abnfRulelist.name:
		mp := map[string]*rule{}

		// Skip heading empty line if exist
		if path.Subpaths[0].MatchRule != "" {
			rltmp, err := lexABNF(input, path.Subpaths[0])
			if err != nil {
				return nil, err
			}
			rl := rltmp.(rule)
			mp[rl.name] = &rl
		}

		for i := 1; i < len(path.Subpaths); i++ {
			sub := path.Subpaths[i].Subpaths[0]

			// Skip empty lines
			if sub.MatchRule != "rule" {
				continue
			}
			rltmp, err := lexABNF(input, sub)
			if err != nil {
				return nil, err
			}
			rl := rltmp.(rule)

			if rule := getRule(rl.name, mp); rule != nil {
				return nil, fmt.Errorf("rule %s already exist", rl.name)
			}
			mp[rl.name] = &rl
		}
		return &Grammar{
			rulemap: mp,
		}, nil

	case abnfRule.name:
		rulename := string(input[path.Subpaths[0].Start:path.Subpaths[0].End])
		pth := path.Subpaths[2].Subpaths[0] // -> rule -> elements -> alternation
		alttmp, err := lexABNF(input, pth)
		if err != nil {
			return nil, err
		}
		return rule{
			name:        rulename,
			alternation: alttmp.(alternation),
		}, nil

	case abnfRulename.name:
		return elemRulename{
			name: string(input[path.Start:path.End]),
		}, nil

	case abnfAlternation.name:
		// Extract first concatenation, must exist
		concatenations := make([]concatenation, 0, 1)
		cnttmp, err := lexABNF(input, path.Subpaths[0])
		if err != nil {
			return nil, err
		}
		concatenations = append(concatenations, cnttmp.(concatenation))

		// If none next, don't start following extraction
		if len(path.Subpaths) == 1 {
			return alternation{
				concatenations: concatenations,
			}, nil
		}

		// Determine first concatenation hit index
		subs := path.Subpaths[1].Subpaths
		icnt := 1
		for {
			if strings.EqualFold(subs[icnt].MatchRule, abnfConcatenation.name) {
				break
			}
			icnt++
		}
		cnttmp, err = lexABNF(input, subs[icnt])
		if err != nil {
			return nil, err
		}
		concatenations = append(concatenations, cnttmp.(concatenation))

		// Following are hits too, last of each subpaths is another concatenation
		for _, sub := range subs[icnt+1:] {
			cnttmp, err := lexABNF(input, sub.Subpaths[len(sub.Subpaths)-1])
			if err != nil {
				return nil, err
			}
			concatenations = append(concatenations, cnttmp.(concatenation))
		}

		return alternation{
			concatenations: concatenations,
		}, nil

	case abnfGroup.name:
		alt := (*Path)(nil)
		for _, sub := range path.Subpaths {
			if strings.EqualFold(sub.MatchRule, abnfAlternation.name) {
				alt = sub
				break
			}
		}
		alttmp, err := lexABNF(input, alt)
		if err != nil {
			return nil, err
		}
		return elemGroup{
			alternation: alttmp.(alternation),
		}, nil

	case abnfConcatenation.name:
		// Extract first repetition, must exist
		repetitions := make([]repetition, 0, 1)
		reptmp, err := lexABNF(input, path.Subpaths[0])
		if err != nil {
			return nil, err
		}
		repetitions = append(repetitions, reptmp.(repetition))

		// If none next, don't start following extraction
		if len(path.Subpaths) == 1 {
			return concatenation{
				repetitions: repetitions,
			}, nil
		}

		// Determine first concatenation hit index
		subs := path.Subpaths[1].Subpaths
		irep := 1
		for {
			if strings.EqualFold(subs[irep].MatchRule, abnfRepetition.name) {
				break
			}
			irep++
		}
		reptmp, err = lexABNF(input, subs[irep])
		if err != nil {
			return nil, err
		}
		repetitions = append(repetitions, reptmp.(repetition))

		// Following are hits too, last of each subpaths is another concatenation
		for _, sub := range subs[irep+1:] {
			reptmp, err := lexABNF(input, sub.Subpaths[len(sub.Subpaths)-1])
			if err != nil {
				return nil, err
			}
			repetitions = append(repetitions, reptmp.(repetition))
		}

		return concatenation{
			repetitions: repetitions,
		}, nil

	case abnfRepetition.name:
		min, max := 1, 1 // default to 1

		var element *Path

		switch len(path.Subpaths) {
		case 1:
			element = path.Subpaths[0]
		case 2:
			repeat := path.Subpaths[0].Subpaths[0].Subpaths[0] // -> option (hit) -> repeat -> hit
			element = path.Subpaths[1]

			// Look for "*" to determine behavior
			spi := (*int)(nil)
			for i := repeat.Start; i < repeat.End; i++ {
				if input[i] == '*' {
					spi = &i
					break
				}
			}

			if spi == nil {
				// If not found, should be exact repetition match
				dstr := string(input[repeat.Start:repeat.End])
				d, _ := strconv.Atoi(dstr)
				min, max = d, d
			} else {
				// Set min
				dstr := string(input[repeat.Start:*spi])
				if dstr == "" {
					min = 0
				} else {
					min, _ = strconv.Atoi(dstr)
				}
				// Set max
				dstr = string(input[*spi+1 : repeat.End])
				if dstr == "" {
					max = inf
				} else {
					max, _ = strconv.Atoi(dstr)
				}
			}
		}

		elemtmp, err := lexABNF(input, element.Subpaths[0])
		if err != nil {
			return nil, err
		}
		return repetition{
			min:     min,
			max:     max,
			element: elemtmp.(elemItf),
		}, nil

	case abnfOption.name:
		ialt := 1
		for {
			if strings.EqualFold(path.Subpaths[ialt].MatchRule, abnfAlternation.name) {
				break
			}
			ialt++
		}
		alttmp, err := lexABNF(input, path.Subpaths[ialt])
		if err != nil {
			return nil, err
		}
		return elemOption{
			alternation: alttmp.(alternation),
		}, nil

	case abnfCharVal.name:
		sensitive := false // by default insensitive (cf. RFC 7405)
		if strings.EqualFold(path.Subpaths[0].MatchRule, abnfCaseSensitiveString.name) {
			sensitive = true
		}

		value := []byte{}
		for _, sub := range path.Subpaths[0].Subpaths {
			if strings.EqualFold(sub.MatchRule, abnfQuotedString.name) {
				value = input[sub.Subpaths[1].Start:sub.Subpaths[1].End]
				break
			}
		}

		return elemCharVal{
			sensitive: sensitive,
			values:    value,
		}, nil

	case abnfProseVal.name:
		values := []string{}
		for i := path.Start + 1; i < path.End-1; i++ {
			values = append(values, string(input[i]))
		}
		return elemProseVal{
			values: values,
		}, nil

	case abnfNumVal.name:
		basePath := path.Subpaths[1].Subpaths[0]
		stat := statSeries
		elems := []string{
			// First hit always at the same spot
			string(input[basePath.Subpaths[1].Start:basePath.Subpaths[1].End]),
		}

		var base string
		switch basePath.MatchRule {
		case abnfBinVal.name:
			base = "b"
		case abnfDecVal.name:
			base = "d"
		case abnfHexVal.name:
			base = "x"
		}

		// Find if series or range
		switch len(basePath.Subpaths) {
		case 3:

		}

		if len(basePath.Subpaths) > 2 {
			hit := basePath.Subpaths[2].Subpaths[0]
			// Could be either serie or range
			splc := input[hit.Subpaths[0].Start:hit.Subpaths[0].End]
			if splc[0] == '-' {
				stat = statRange
			}

			// Second hit always at the same spot
			elems = append(elems, string(input[hit.Subpaths[1].Start:hit.Subpaths[1].End]))

			// Other follows in their own subpaths
			for i := 2; i < len(hit.Subpaths); i++ {
				t := hit.Subpaths[i]
				elems = append(elems, string(input[t.Subpaths[1].Start:t.Subpaths[1].End]))
			}
		}

		return elemNumVal{
			base:   base,
			status: stat,
			elems:  elems,
		}, nil
	}

	if len(path.Subpaths) == 1 && path.MatchRule == "" {
		return lexABNF(input, path.Subpaths[0])
	}

	from := path.Start - 10
	if from < 0 {
		from = 0
	}
	to := path.End + 10
	if to > len(input) {
		to = len(input)
	}
	panic(fmt.Sprintf("unhandlable path from %d to %d: \"%s\" ; sneek peak around \"%s\"", path.Start, path.End, input[path.Start:path.End], input[from:to]))
}

// SemvalABNF proceed to semantic validations of an ABNF grammar.
// It currently support the following checks:
// - for all rules, its dependencies (rules) exist
// - for repetition, min <= max
// To update this list, please open an issue.
func SemvalABNF(g *Grammar) error {
	// Check all dependencies exist
	for _, rule := range g.rulemap {
		deps := getDependencies(rule.alternation)
		for _, dep := range deps {
			r := getRule(dep, g.rulemap)
			if r == nil {
				return fmt.Errorf("missing dependency (rule) %s", dep)
			}
		}
	}

	for _, rule := range g.rulemap {
		if err := semvalAlternation(rule.alternation); err != nil {
			return err
		}
	}
	return nil
}

func semvalAlternation(alt alternation) error {
	for _, concat := range alt.concatenations {
		for _, rep := range concat.repetitions {
			// min <= max
			if rep.max != inf && rep.min > rep.max {
				return fmt.Errorf("invalid semantic of input ABNF grammar for repetition %s", rep.String())
			}
			switch elem := rep.element.(type) {
			case elemGroup:
				if err := semvalAlternation(elem.alternation); err != nil {
					return err
				}
			case elemOption:
				if err := semvalAlternation(elem.alternation); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
