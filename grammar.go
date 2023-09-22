package goabnf

import (
	"fmt"
	"strconv"
	"strings"
)

// Grammar represents an ABNF grammar as defined by RFC 5234.
// It is constituted of a set of rules with an unique name.
type Grammar struct {
	Rulemap map[string]*Rule
}

// IsValid checks there exist at least a path that completly consumes
// input, hence is valide given this gramma and especially one of its
// rule.
// XXX can fail if the rulename can't safely generate
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
	for _, rule := range g.Rulemap {
		str += rule.String() + "\r\n"
	}
	return str
}

// PrettyPrint returns a prettified string that represents the grammar.
func (g *Grammar) PrettyPrint() string {
	// Determine maximum rulename length
	rulenameLength := 0
	for rulename := range g.Rulemap {
		if len(rulename) > rulenameLength {
			rulenameLength = len(rulename)
		}
	}

	// Construct output
	out := ""
	for rulename, rl := range g.Rulemap {
		spaces := ""
		for i := 0; i < rulenameLength-len(rulename); i++ {
			spaces += " "
		}

		out += fmt.Sprintf("%s%s = %s\r\n", rulename, spaces, rl.Alternation)
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
		return nil, ErrNoSolutionFound
	case 1:
		path = paths[0]
	default:
		return nil, &ErrMultipleSolutionsFound{
			Paths: paths,
		}
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
	rootRule := GetRule(rootRulename, grammar.Rulemap)
	if rootRule == nil {
		return nil, &ErrRuleNotFound{
			Rulename: rootRulename,
		}
	}

	// Parse input with grammar's initial rule
	possibilites := solveAlt(grammar, rootRule.Alternation, input, 0)

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

func solveAlt(grammar *Grammar, alt Alternation, input []byte, index int) []*Path {
	altPossibilities := []*Path{}

	for _, concat := range alt.Concatenations {
		cntPossibilities := []*Path{}

		// Init with first repetition (guarantee of at least 1 repetition)
		possibilities := solveRep(grammar, concat.Repetitions[0], input, index)
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
		for i := 1; i < len(concat.Repetitions); i++ {
			rep := concat.Repetitions[i]

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

func solveRep(grammar *Grammar, rep Repetition, input []byte, index int) []*Path {
	// Fast check won't be out of bounds with first read
	if !solveKeepGoing(rep, input, index, 0) {
		return []*Path{}
	}

	// Find first repetition paths.
	paths := solveElem(grammar, rep.Element, input, index)
	pindex := 0

	y := 1
	kg := solveKeepGoing(rep, input, index, y)

	for kg {
		iterPaths := []*Path{}
		for _, poss := range paths[pindex:] {
			elemPossibilities := solveElem(grammar, rep.Element, input, poss.End)
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
		if y >= rep.Min {
			pindex += len(paths) - pindex
			paths = append(paths, iterPaths...)
		}
	}

	// Add empty solution if is a valid path
	if rep.Min == 0 {
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

func solveElem(grammar *Grammar, elem ElemItf, input []byte, index int) []*Path {
	paths := []*Path{}

	switch v := elem.(type) {
	case ElemRulename:
		rule := GetRule(v.Name, grammar.Rulemap)
		possibilities := solveAlt(grammar, rule.Alternation, input, index)
		for _, poss := range possibilities {
			poss.MatchRule = v.Name
			paths = append(paths, poss)
		}

	case ElemOption:
		paths = solveRep(grammar, Repetition{
			Min:     0,
			Max:     1,
			Element: ElemGroup(v),
		}, input, index)

	case ElemGroup:
		paths = solveAlt(grammar, v.Alternation, input, index)

	case ElemNumVal:
		switch v.Status {
		case StatRange:
			// Any matches
			min, max := atob(v.Elems[0], v.Base), atob(v.Elems[1], v.Base)
			if min <= input[index] && input[index] <= max {
				paths = append(paths, &Path{
					Subpaths:  nil,
					MatchRule: "",
					Start:     index,
					End:       index + 1,
				})
			}

		case StatSeries:
			// Only match if all matches in order
			initialIndex := index
			matches := true
			for i := 0; i < len(v.Elems) && matches; i++ {
				if atob(v.Elems[i], v.Base) != input[index] {
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

	case ElemProseVal:
		panic("elemProseVal")

	case ElemCharVal:
		initialIndex := index
		matches := true
		for i := 0; i < len(v.Values) && matches; i++ {
			if sensequal(v.Values[i], input[index], v.Sensitive) {
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
func solveKeepGoing(rep Repetition, input []byte, index, y int) bool {
	// Find if could handle the length of this repetition
	// considering its type
	couldHandle := true
	switch v := rep.Element.(type) {
	case ElemNumVal:
		// Check only one byte
		couldHandle = index < len(input)

	case ElemCharVal:
		// Check current index+length of char value string is not longer than the input
		couldHandle = index+len(v.Values)-1 < len(input)

	case ElemProseVal:
		panic("elemProseVal")
	}

	// If no maximum repetition, only bound to input length thus
	// if it could handle its consumption given repetition's type
	if rep.Max == inf {
		return couldHandle
	}
	// If has a maximum repetition, check could handle AND will remain
	// under boundary.
	return couldHandle && y < rep.Max
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
	case abnfRulelist.Name:
		mp := map[string]*Rule{}

		// Skip heading empty line if exist
		if path.Subpaths[0].MatchRule != "" {
			rltmp, err := lexABNF(input, path.Subpaths[0])
			if err != nil {
				return nil, err
			}
			rl := rltmp.(Rule)
			mp[rl.Name] = &rl
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
			rl := rltmp.(Rule)

			if rule := GetRule(rl.Name, mp); rule != nil {
				return nil, &ErrDuplicatedRule{
					Rulename: rl.Name,
				}
			}
			mp[rl.Name] = &rl
		}
		return &Grammar{
			Rulemap: mp,
		}, nil

	case abnfRule.Name:
		rulename := string(input[path.Subpaths[0].Start:path.Subpaths[0].End])
		pth := path.Subpaths[2].Subpaths[0] // -> rule -> elements -> alternation
		alttmp, err := lexABNF(input, pth)
		if err != nil {
			return nil, err
		}
		return Rule{
			Name:        rulename,
			Alternation: alttmp.(Alternation),
		}, nil

	case abnfRulename.Name:
		return ElemRulename{
			Name: string(input[path.Start:path.End]),
		}, nil

	case abnfAlternation.Name:
		// Extract first concatenation, must exist
		concatenations := make([]Concatenation, 0, 1)
		cnttmp, err := lexABNF(input, path.Subpaths[0])
		if err != nil {
			return nil, err
		}
		concatenations = append(concatenations, cnttmp.(Concatenation))

		// If none next, don't start following extraction
		if len(path.Subpaths) == 1 {
			return Alternation{
				Concatenations: concatenations,
			}, nil
		}

		// Determine first concatenation hit index
		subs := path.Subpaths[1].Subpaths
		icnt := 1
		for {
			if strings.EqualFold(subs[icnt].MatchRule, abnfConcatenation.Name) {
				break
			}
			icnt++
		}
		cnttmp, err = lexABNF(input, subs[icnt])
		if err != nil {
			return nil, err
		}
		concatenations = append(concatenations, cnttmp.(Concatenation))

		// Following are hits too, last of each subpaths is another concatenation
		for _, sub := range subs[icnt+1:] {
			cnttmp, err := lexABNF(input, sub.Subpaths[len(sub.Subpaths)-1])
			if err != nil {
				return nil, err
			}
			concatenations = append(concatenations, cnttmp.(Concatenation))
		}

		return Alternation{
			Concatenations: concatenations,
		}, nil

	case abnfGroup.Name:
		alt := (*Path)(nil)
		for _, sub := range path.Subpaths {
			if strings.EqualFold(sub.MatchRule, abnfAlternation.Name) {
				alt = sub
				break
			}
		}
		alttmp, err := lexABNF(input, alt)
		if err != nil {
			return nil, err
		}
		return ElemGroup{
			Alternation: alttmp.(Alternation),
		}, nil

	case abnfConcatenation.Name:
		// Extract first repetition, must exist
		repetitions := make([]Repetition, 0, 1)
		reptmp, err := lexABNF(input, path.Subpaths[0])
		if err != nil {
			return nil, err
		}
		repetitions = append(repetitions, reptmp.(Repetition))

		// If none next, don't start following extraction
		if len(path.Subpaths) == 1 {
			return Concatenation{
				Repetitions: repetitions,
			}, nil
		}

		// Determine first concatenation hit index
		subs := path.Subpaths[1].Subpaths
		irep := 1
		for {
			if strings.EqualFold(subs[irep].MatchRule, abnfRepetition.Name) {
				break
			}
			irep++
		}
		reptmp, err = lexABNF(input, subs[irep])
		if err != nil {
			return nil, err
		}
		repetitions = append(repetitions, reptmp.(Repetition))

		// Following are hits too, last of each subpaths is another concatenation
		for _, sub := range subs[irep+1:] {
			reptmp, err := lexABNF(input, sub.Subpaths[len(sub.Subpaths)-1])
			if err != nil {
				return nil, err
			}
			repetitions = append(repetitions, reptmp.(Repetition))
		}

		return Concatenation{
			Repetitions: repetitions,
		}, nil

	case abnfRepetition.Name:
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
		return Repetition{
			Min:     min,
			Max:     max,
			Element: elemtmp.(ElemItf),
		}, nil

	case abnfOption.Name:
		ialt := 1
		for {
			if strings.EqualFold(path.Subpaths[ialt].MatchRule, abnfAlternation.Name) {
				break
			}
			ialt++
		}
		alttmp, err := lexABNF(input, path.Subpaths[ialt])
		if err != nil {
			return nil, err
		}
		return ElemOption{
			Alternation: alttmp.(Alternation),
		}, nil

	case abnfCharVal.Name:
		sensitive := false // by default insensitive (cf. RFC 7405)
		if strings.EqualFold(path.Subpaths[0].MatchRule, abnfCaseSensitiveString.Name) {
			sensitive = true
		}

		value := []byte{}
		for _, sub := range path.Subpaths[0].Subpaths {
			if strings.EqualFold(sub.MatchRule, abnfQuotedString.Name) {
				value = input[sub.Subpaths[1].Start:sub.Subpaths[1].End]
				break
			}
		}

		return ElemCharVal{
			Sensitive: sensitive,
			Values:    value,
		}, nil

	case abnfProseVal.Name:
		values := []string{}
		for i := path.Start + 1; i < path.End-1; i++ {
			values = append(values, string(input[i]))
		}
		return ElemProseVal{
			values: values,
		}, nil

	case abnfNumVal.Name:
		basePath := path.Subpaths[1].Subpaths[0]
		stat := StatSeries
		elems := []string{
			// First hit always at the same spot
			string(input[basePath.Subpaths[1].Start:basePath.Subpaths[1].End]),
		}

		var base string
		switch basePath.MatchRule {
		case abnfBinVal.Name:
			base = "b"
		case abnfDecVal.Name:
			base = "d"
		case abnfHexVal.Name:
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
				stat = StatRange
			}

			// Second hit always at the same spot
			elems = append(elems, string(input[hit.Subpaths[1].Start:hit.Subpaths[1].End]))

			// Other follows in their own subpaths
			for i := 2; i < len(hit.Subpaths); i++ {
				t := hit.Subpaths[i]
				elems = append(elems, string(input[t.Subpaths[1].Start:t.Subpaths[1].End]))
			}
		}

		return ElemNumVal{
			Base:   base,
			Status: stat,
			Elems:  elems,
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
	for _, rule := range g.Rulemap {
		deps := getDependencies(rule.Alternation)
		for _, dep := range deps {
			r := GetRule(dep, g.Rulemap)
			if r == nil {
				return &ErrDependencyNotFound{
					Rulename: dep,
				}
			}
		}
	}

	for _, rule := range g.Rulemap {
		if err := semvalAlternation(rule.Alternation); err != nil {
			return err
		}
	}
	return nil
}

func semvalAlternation(alt Alternation) error {
	for _, concat := range alt.Concatenations {
		for _, rep := range concat.Repetitions {
			// min <= max
			if rep.Max != inf && rep.Min > rep.Max {
				return &ErrSemanticRepetition{
					Repetition: rep,
				}
			}
			switch elem := rep.Element.(type) {
			case ElemGroup:
				if err := semvalAlternation(elem.Alternation); err != nil {
					return err
				}
			case ElemOption:
				if err := semvalAlternation(elem.Alternation); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
