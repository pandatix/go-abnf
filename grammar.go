package goabnf

import (
	"errors"
	"fmt"
	"strconv"
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
func (g *Grammar) Validate(input []byte) bool {
	return false
}

// ABNF returns string representation of the grammar that is valid
// according to the ABNF specifications/RFCs.
// This notably imply the use of CRLF instead of LF, and does not
// preserve the initial order nor pretty print it.
// TODO implement PrettyPrint
func (g *Grammar) ABNF() string {
	str := ""
	for _, rule := range g.rulemap {
		str += rule.String() + "\r\n"
	}
	return str
}

// Path represents a portion of an input that matched a rule from
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
func ParseABNF(input []byte) (*Grammar, error) {
	// Parse input with ABNF grammar
	path, err := Parse(input, ABNF, "rulelist")
	if err != nil {
		return nil, err
	}

	// Lex path
	g, err := LexABNF(input, path)
	if err != nil {
		return nil, err
	}

	// TODO validate all dependencies (rule) exist

	return g, nil
}

// Parse parses an ABNF-compliant input using a grammar.
// It uses uses a top-down parsing strategy using backtracking in
// order to look for solutions. If many are found, it raises an error.
// If the input is invalid (gramatically, incomplete...) it returns
// an error of type *ErrParse.
func Parse(input []byte, grammar *Grammar, rootRulename string) (*Path, error) {
	// Select root rule to begin with
	rootRule, ok := grammar.rulemap[rootRulename]
	if !ok {
		return nil, fmt.Errorf("root rule %s not found", rootRulename)
	}

	// Parse input with grammar's initial rule
	possibilites := solveAlt(grammar, rootRule.alternation, input, 0)

	// Look for solutions that consumed the whole input
	outPoss := (*Path)(nil)
	for _, poss := range possibilites {
		if poss.End == len(input) {
			if outPoss != nil {
				panic("multiple solves, please open an issue. This could eventually need an Erratum from IETF tracking")
			}
			outPoss = poss.Subpaths[0]
		}
	}
	if outPoss == nil {
		return nil, errors.New("got no possibilities")
	}
	outPoss.MatchRule = rootRulename
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
	if !keepGoing(rep, input, index, 0) {
		return []*Path{}
	}

	// Find first repetition paths.
	paths := solveElem(grammar, rep.element, input, index)
	pindex := 0

	y := 1
	kg := keepGoing(rep, input, index, y)

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
		kg = keepGoing(rep, input, index, y)

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
			for _, elem := range v.elems {
				if atob(elem, v.base) == input[index] {
					paths = append(paths, &Path{
						Subpaths:  nil,
						MatchRule: "",
						Start:     index,
						End:       index + 1,
					})
					break // don't need to go further, check only one byte
				}
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

// keepGoing returns true if a new repetition should be tested or not.
// If the repetition has no max, it returns whether input has been
// totally consumed.
// Else, it checks if input has been totally consumed AND if there
// could be other repetitions.
func keepGoing(rep repetition, input []byte, index, y int) bool {
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

// getRule returns the rule by the given rulename, wether
// it is a core rule or present in the grammar.
func getRule(rulename string, rulemap map[string]*rule) *rule {
	if r, ok := coreRules[rulename]; ok {
		return r
	}
	return rulemap[rulename]
}

// LexABNF is the lexer for the ABNF structrual model implemented.
func LexABNF(input []byte, path *Path) (*Grammar, error) {
	g, err := lexABNF(input, path)
	if err != nil {
		return nil, err
	}
	return g.(*Grammar), nil
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
			rl := path.Subpaths[i].Subpaths[0]

			// Skip empty lines
			if rl.MatchRule != "rule" {
				continue
			}
			rltmp, err := lexABNF(input, rl)
			if err != nil {
				return nil, err
			}
			rule := rltmp.(rule)

			if r := getRule(rule.name, mp); r != nil {
				return nil, fmt.Errorf("rule %s already exist", rule.name)
			}
			mp[rule.name] = &rule
		}
		return &Grammar{
			rulemap: mp,
		}, nil

	case abnfRule.name:
		rulename := string(input[path.Subpaths[0].Start:path.Subpaths[0].End])
		alt := path.Subpaths[2].Subpaths[0] // -> rule -> elements -> alternation

		alttmp, err := lexABNF(input, alt)
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
		concatenations := make([]concatenation, 1)
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
			if subs[icnt].MatchRule == "concatenation" {
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
			if sub.MatchRule == "alternation" {
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
		repetitions := make([]repetition, 1)
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
			if subs[irep].MatchRule == "repetition" {
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
			reptmp, err = lexABNF(input, sub.Subpaths[len(sub.Subpaths)-1])
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
			if path.Subpaths[ialt].MatchRule == "alternation" {
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
		if path.Subpaths[0].MatchRule == abnfCaseSensitiveString.name {
			sensitive = true
		}

		value := []byte{}
		for _, sub := range path.Subpaths[0].Subpaths {
			if sub.MatchRule == abnfQuotedString.name {
				value = input[sub.Subpaths[1].Start:sub.Subpaths[1].End]
				break
			}
		}

		return elemCharVal{
			sensitive: sensitive,
			values:    value,
		}, nil

	case abnfNumVal.name:
		basePath := path.Subpaths[1].Subpaths[0]
		stat := statSeries
		elems := []string{}

		var base string
		switch basePath.MatchRule {
		case abnfBinVal.name:
			base = "b"
		case abnfDecVal.name:
			base = "d"
		case abnfHexVal.name:
			base = "x"
		}

		elems = append(elems, string(input[basePath.Subpaths[1].Start:basePath.Subpaths[1].End]))

		switch len(basePath.Subpaths) {
		case 3:
			// Could be either serie or oneof range
			spl := basePath.Subpaths[2].Subpaths[0].Subpaths[0]
			splc := input[spl.Start:spl.End]
			if splc[0] == '-' {
				stat = statRange
			}
		}

		for i := 2; i < len(basePath.Subpaths); i++ {
			val := basePath.Subpaths[i].Subpaths[0].Subpaths[1]
			elems = append(elems, string(input[val.Start:val.End]))
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
