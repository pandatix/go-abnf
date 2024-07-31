package goabnf

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	uuid "github.com/hashicorp/go-uuid"
)

// TransitionGraph represent a grammar transition graph.
// It contains the list of entrypoints and endpoints.
// You could travel through the graph starting from the entrypoints.
type TransitionGraph struct {
	Entrypoints []*Node
	Endpoints   []*Node
}

// Node of a TransitionGraph.
// Unically identifiate the node of the transition graph along
// with its underlying element and its next nodes.
type Node struct {
	ID   string
	Elem ElemItf

	Nexts []*Node
}

// TransitionGraph builds a transition graph out of a grammar
// and the given rulename.
// TODO it is possible to build transition graph out of cylic rules iif	it is not concatenated to another repetition (can't pipe O->I as there is no O). For instance, `a = "a" a` can exist.
func (g *Grammar) TransitionGraph(rulename string, opts ...TGOption) (*TransitionGraph, error) {
	// Build transition graph machine
	options := &tgoptions{
		deflateRules:        false,
		deflateNumVals:      false,
		deflateCharVals:     false,
		repetitionThreshold: 256,
	}
	for _, opt := range opts {
		opt.apply(options)
	}
	m := &tgmachine{
		options: options,
		grammar: g,
		buf:     map[string][2][]*Node{},
	}

	// Find the rule
	rule := GetRule(rulename, g.Rulemap)
	if rule == nil {
		return nil, &ErrRuleNotFound{
			Rulename: rulename,
		}
	}

	// Ensure the rule is semantically valid and does not contain cycle.
	// Semantic validity is required to ensure rule dependencies actually
	// exist, while no cycle is required because the algorithm is recursive
	// and may not stop else.
	if options.deflateRules {
		if err := SemvalABNF(g); err != nil {
			return nil, err
		}
	}
	cycle, err := g.RuleContainsCycle(rulename)
	if err != nil {
		return nil, err
	}
	if cycle {
		return nil, &ErrCyclicRule{
			Rulename: rulename,
		}
	}

	// Build transition graph
	entrypoints, endpoints, err := m.altGraph(rule.Alternation)
	if err != nil {
		return nil, err
	}
	return &TransitionGraph{
		Entrypoints: entrypoints,
		Endpoints:   endpoints,
	}, nil
}

var (
	// The empty node enable to bridge the no-entrypoint case of a repetition.
	// This occurs when the minimum is 0.
	// It disappear as soon as the repetition is piped as an input from lower
	// inputs to upper outputs.
	emptyNode = (*Node)(nil)
)

type tgoptions struct {
	deflateRules        bool
	deflateNumVals      bool
	deflateCharVals     bool
	repetitionThreshold int
}

type TGOption interface {
	apply(opts *tgoptions)
}

type deflateRulesOption bool

func (opt deflateRulesOption) apply(opts *tgoptions) {
	opts.deflateRules = bool(opt)
}

// WithDeflateRules when passed to true, will recursively build the transition
// graphs of the rules it uses (reuse them if possible) and concatenate the
// sub transition graphs.
// It generates a more complex but exhaustive transition graph.
func WithDeflateRules(deflate bool) TGOption {
	return deflateRulesOption(deflate)
}

var _ TGOption = deflateRulesOption(false)

type deflateNumValsOption bool

func (opt deflateNumValsOption) apply(opts *tgoptions) {
	opts.deflateNumVals = bool(opt)
}

// WithDeflateNumVals when passed to true, will replace a single node representing
// the ranges or series of multiple numeric values to individual nodes.
// It generates a more complex but exhaustive transition graph.
func WithDeflateNumVals(deflate bool) TGOption {
	return deflateNumValsOption(deflate)
}

var _ TGOption = deflateNumValsOption(false)

type deflateCharVals bool

func (opt deflateCharVals) apply(opts *tgoptions) {
	opts.deflateCharVals = bool(opt)
}

// WithDeflateCharVals when passed to true, will replace a single node representing
// the char value to an exhaustive concatenation of all characters (lower and upper
// case) and the transitions between them.
func WithDeflateCharVals(deflate bool) TGOption {
	return deflateCharVals(deflate)
}

var _ TGOption = deflateCharVals(false)

type repetitionThreshold int

func (opt repetitionThreshold) apply(opts *tgoptions) {
	opts.repetitionThreshold = int(opt)
}

// WithRepetitionThreshold defines the threshold to block a large repetition
// to occur, elseway it may consum all memory to build the transition graph.
// For instance, a rule defined as follows may self-DoS go-abnf.
//
// a = 9555("a")
//
// WARNING it does not avoid such memory consumption on chained repetitions.
// For instance, the two following cases could produce large transition graphs
// without control with this functional option.
//
// a = 10( 10( 10("a") ) )
//
// a = 10 ( 10*"a" ( 10"a" 9"a" 8"a" ) / ( *10"a" *10"a" *10"a" ) ) 10"a"
//
// Defaults to 256.
func WithRepetitionThreshold(threshold int) TGOption {
	return repetitionThreshold(threshold)
}

type tgmachine struct {
	options *tgoptions
	grammar *Grammar
	buf     map[string][2][]*Node
}

func (m *tgmachine) altGraph(alt Alternation) (entrypoints []*Node, endpoints []*Node, err error) {
	for _, concat := range alt.Concatenations {
		ci, co, err := m.concatGraph(concat)
		if err != nil {
			return nil, nil, err
		}

		// Group concatenation inputs, but avoid duplicating the emptyNode
		entryHasEmpty := slices.Contains(entrypoints, emptyNode)
		for _, vci := range ci {
			if vci == emptyNode && entryHasEmpty {
				continue
			}
			entrypoints = append(entrypoints, vci)
		}

		// Group concatenation outputs, but avoid duplicating the emptyNode
		endHasEmpty := slices.Contains(endpoints, emptyNode)
		for _, vco := range co {
			if vco == emptyNode && endHasEmpty {
				continue
			}
			endpoints = append(endpoints, vco)
		}
	}
	return
}

func (m *tgmachine) concatGraph(concat Concatenation) (entrypoints []*Node, endpoints []*Node, err error) {
	ci, co, err := m.repGraph(concat.Repetitions[0])
	if err != nil {
		return nil, nil, err
	}
	for i := 1; i < len(concat.Repetitions); i++ {
		repi, repo, err := m.repGraph(concat.Repetitions[i])
		if err != nil {
			return nil, nil, err
		}
		ci, co = concatTransitionGraphs(ci, co, repi, repo)
	}
	return ci, co, nil
}

func concatTransitionGraphs(prevI, prevO, currI, currO []*Node) (entrypoints []*Node, endpoints []*Node) {
	// If prevI contains the emptyNode it means currI (possibly with
	// the emptyNode) is also part of the entrypoints (without prevI's
	// emptyNode).
	if slices.Contains(prevI, emptyNode) {
		for _, vprevI := range prevI {
			if vprevI == emptyNode {
				continue
			}
			entrypoints = append(entrypoints, vprevI)
		}
		entrypoints = append(entrypoints, currI...)
	} else {
		entrypoints = prevI
	}

	// plug previous outputs (prevO) to current inputs (currI).
	for _, vprevO := range prevO {
		if vprevO == emptyNode {
			continue
		}
		for _, vrepi := range currI {
			if vrepi == emptyNode {
				continue
			}
			vprevO.Nexts = append(vprevO.Nexts, vrepi)
		}
	}

	// new concatenation output is the previous ones if current
	// inputs contains the emptyNode (repetition is skippable),
	// and the current outputs ones.
	if slices.Contains(currI, emptyNode) {
		endpoints = append(endpoints, prevO...)
	}
	for _, vrepo := range currO {
		if vrepo == emptyNode {
			continue
		}
		endpoints = append(endpoints, vrepo)
	}

	return
}

func (m *tgmachine) repGraph(rep Repetition) (entrypoints []*Node, endpoints []*Node, err error) {
	// element entry-/end-points (resp. I/O)
	elemi, elemo, err := m.elemGraph(rep.Element)
	if err != nil {
		return nil, nil, err
	}

	if rep.Min == 0 {
		entrypoints = appendNodes(entrypoints, emptyNode)
		endpoints = appendNodes(endpoints, emptyNode)

		switch rep.Max {
		case 1:
			// min = 0 & max = 1: optional v
			entrypoints = appendNodes(entrypoints, elemi...)
			endpoints = appendNodes(endpoints, elemo...)
		case inf:
			// min = 0 & max = inf: optional infinity
			elemiNoEmpty := []*Node{}
			for _, velemi := range elemi {
				if velemi == emptyNode {
					continue
				}
				elemiNoEmpty = appendNodes(elemiNoEmpty, velemi)
			}
			for _, velemo := range elemo {
				if velemo == emptyNode {
					continue
				}
				velemo.Nexts = appendNodes(velemo.Nexts, elemiNoEmpty...)
			}
			entrypoints = appendNodes(entrypoints, elemi...)
			endpoints = appendNodes(endpoints, elemo...)

		default:
			// min = 0 & 1 < max < inf: optional to n
			if rep.Max > m.options.repetitionThreshold {
				return nil, nil, errors.New("repetition threshold reached")
			}
			tgs, chi, _ := chainTransitionGraph(elemi, elemo, rep.Max)
			entrypoints = appendNodes(entrypoints, chi...)
			for _, tg := range tgs {
				endpoints = appendNodes(endpoints, tg.Endpoints...)
			}
		}
	} else {
		switch rep.Max {
		case 1:
			// min == 1 & max == 1: mandatory
			if rep.Min != 1 {
				return nil, nil, errors.New("minimum must be 1")
			}
			entrypoints = appendNodes(entrypoints, elemi...)
			endpoints = appendNodes(endpoints, elemo...)

		case inf:
			// min >= 1 && max = inf: n to infinity
			if rep.Min > m.options.repetitionThreshold {
				return nil, nil, errors.New("repetition threshold reached")
			}
			tgs, chi, cho := chainTransitionGraph(elemi, elemo, rep.Min+1)
			entrypoints = appendNodes(entrypoints, chi...)
			endpoints = appendNodes(endpoints, cho...)

			last := tgs[len(tgs)-1]
			for _, vo := range last.Endpoints {
				if vo == emptyNode {
					continue
				}
				for _, etp := range last.Entrypoints {
					// Make sure to not append the empty node as a next node, this is not possible
					if etp == emptyNode {
						continue
					}
					vo.Nexts = appendNodes(vo.Nexts, etp)
				}
			}

		default:
			// min >= 1 && max < inf: n to m
			if rep.Min > rep.Max {
				return nil, nil, errors.New("repetition minimum > maximum")
			}
			if rep.Max > m.options.repetitionThreshold {
				return nil, nil, errors.New("repetition threshold reached")
			}

			// Build the flat chain (not endpoints, except last)
			firstI, lastO := elemi, elemo
			if rep.Min > 1 {
				_, firstI, lastO = chainTransitionGraph(elemi, elemo, rep.Min)
			}
			entrypoints = appendNodes(entrypoints, firstI...)
			endpoints = appendNodes(endpoints, lastO...)

			// Build remaining endpoints
			remaining := rep.Max - rep.Min
			if remaining > 0 {
				tgs, chi, _ := chainTransitionGraph(elemi, elemo, rep.Max-rep.Min)
				for _, tg := range tgs {
					endpoints = appendNodes(endpoints, tg.Endpoints...)
				}
				for _, vlasto := range lastO {
					if vlasto == emptyNode {
						continue
					}
					for _, nchi := range chi {
						if nchi == emptyNode {
							continue
						}
						vlasto.Nexts = appendNodes(vlasto.Nexts, nchi)
					}
				}
			}
		}
	}

	return
}

func chainTransitionGraph(i, o []*Node, n int) (tgs []TransitionGraph, entrypoints []*Node, endpoints []*Node) {
	// Make sure to not chain... nothing ¯\_(ツ)_/¯
	if n == 0 {
		return
	}
	tgs = make([]TransitionGraph, n)

	// Init chaining
	entrypoints, endpoints = cloneTransitionGraph(i, o)
	tgs[0] = TransitionGraph{
		Entrypoints: entrypoints,
		Endpoints:   endpoints,
	}

	// Gotta chain them all
	for j := 1; j < n; j++ {
		nextI, nextO := cloneTransitionGraph(i, o)
		tgs[j] = TransitionGraph{
			Entrypoints: nextI,
			Endpoints:   nextO,
		}
		entrypoints, endpoints = concatTransitionGraphs(entrypoints, endpoints, nextI, nextO)
	}
	return
}

func cloneTransitionGraph(i, o []*Node) (entrypoints []*Node, endpoints []*Node) {
	// Traverse graph to map all cloned originToNewNodes by their origin IDs
	originToNewNodes := map[string]cnode{}
	for _, vi := range i {
		if vi == emptyNode {
			continue
		}
		cloneTG(originToNewNodes, vi)
	}

	// Rebuild links
	for _, cnode := range originToNewNodes {
		nnxts := make([]*Node, 0, len(cnode.origin.Nexts))
		for _, onext := range cnode.origin.Nexts {
			nnxts = append(nnxts, originToNewNodes[onext.ID].cloned)
		}
		cnode.cloned.Nexts = nnxts
	}

	// Get cloned I/O
	entrypoints = make([]*Node, 0, len(i))
	for _, vi := range i {
		if vi == emptyNode {
			entrypoints = append(entrypoints, emptyNode)
			continue
		}
		entrypoints = append(entrypoints, originToNewNodes[vi.ID].cloned)
	}
	endpoints = make([]*Node, 0, len(o))
	for _, vo := range o {
		if vo == emptyNode {
			endpoints = append(endpoints, emptyNode)
			continue
		}
		endpoints = append(endpoints, originToNewNodes[vo.ID].cloned)
	}
	return
}

type cnode struct {
	origin, cloned *Node
}

func cloneTG(originToNewNodes map[string]cnode, origin *Node) {
	id, _ := uuid.GenerateUUID()

	originToNewNodes[origin.ID] = cnode{
		origin: origin,
		cloned: &Node{
			ID:    id,
			Elem:  origin.Elem,
			Nexts: nil, // will map it later, requires all origins to be cloned first
		},
	}

	// recurse iif not known yet
	for _, n := range origin.Nexts {
		if _, ok := originToNewNodes[n.ID]; ok {
			continue
		}
		cloneTG(originToNewNodes, n)
	}
}

func appendNodes(existing []*Node, news ...*Node) []*Node {
	for _, n := range news {
		if slices.Contains(existing, n) {
			continue
		}
		existing = append(existing, n)
	}
	return existing
}

func (m *tgmachine) elemGraph(elem ElemItf) (entrypoints []*Node, endpoints []*Node, err error) {
	switch v := elem.(type) {
	// Final elements => create the node, no need to pipe I/O
	case ElemCharVal:
		if len(v.Values) == 0 {
			entrypoints = append(entrypoints, emptyNode)
			endpoints = append(endpoints, emptyNode)
			return
		}

		if !m.options.deflateCharVals {
			n := newNode(v)
			entrypoints = append(entrypoints, n)
			endpoints = append(endpoints, n)
			return
		}

		var prevs []*Node = nil
		var curr []*Node = nil
		for _, b := range v.Values {
			isLower := b >= 'a' && b <= 'z'
			isUpper := b >= 'A' && b <= 'Z'
			requireBoth := (isLower || isUpper) && !v.Sensitive

			if !requireBoth {
				n := newNode(ElemCharVal{
					Sensitive: true,
					Values:    []byte{b},
				})
				curr = []*Node{n}

				if prevs == nil {
					entrypoints = append(entrypoints, n)
				}
				for _, v := range prevs {
					v.Nexts = append(v.Nexts, curr...)
				}
				prevs = []*Node{n}
			} else {
				nlv := b
				if isUpper {
					nlv = b - 'A' + 'a'
				}
				nuv := b
				if isLower {
					nuv = b - 'a' + 'A'
				}

				nl := newNode(ElemCharVal{
					Sensitive: true,
					Values:    []byte{nlv},
				})
				nu := newNode(ElemCharVal{
					Sensitive: true,
					Values:    []byte{nuv},
				})
				curr = []*Node{nl, nu}

				if prevs == nil {
					entrypoints = append(entrypoints, nl, nu)
				}
				for _, v := range prevs {
					v.Nexts = append(v.Nexts, curr...)
				}
				prevs = []*Node{nl, nu}
			}
		}
		endpoints = append(endpoints, curr...)
		return

	case ElemNumVal:
		if !m.options.deflateNumVals {
			n := newNode(v)
			entrypoints = append(entrypoints, n)
			endpoints = append(endpoints, n)
			return
		}
		switch v.Status {
		case StatRange:
			min, max := atob(v.Elems[0], v.Base), atob(v.Elems[1], v.Base)
			for b := min; b <= max; b++ {
				s := btoa(b, v.Base)

				n := newNode(ElemNumVal{
					Base:   v.Base,
					Status: StatSeries,
					Elems:  []string{s},
				})
				entrypoints = append(entrypoints, n)
				endpoints = append(endpoints, n)
			}

		case StatSeries:
			for _, s := range v.Elems {
				n := newNode(ElemNumVal{
					Base:   v.Base,
					Status: StatSeries,
					Elems:  []string{s},
				})
				entrypoints = append(entrypoints, n)
				endpoints = append(endpoints, n)
			}
		}
		return

	// Recursive elements => pipe I/O
	case ElemRulename:
		if m.options.deflateRules {
			name := strings.ToLower(v.Name)
			if n, ok := m.buf[name]; ok {
				entrypoints, endpoints := cloneTransitionGraph(n[0], n[1])
				return entrypoints, endpoints, nil
			}
			rule := GetRule(v.Name, m.grammar.Rulemap)
			if rule == nil {
				return nil, nil, &ErrRuleNotFound{
					Rulename: v.Name,
				}
			}
			i, o, err := m.altGraph(rule.Alternation)
			if err != nil {
				return nil, nil, err
			}
			ni, no := cloneTransitionGraph(i, o)
			m.buf[name] = [2][]*Node{ni, no}
			return i, o, nil
		}
		n := newNode(v)
		entrypoints = append(entrypoints, n)
		endpoints = append(endpoints, n)
		return

	case ElemOption:
		elemi, elemo, err := m.altGraph(v.Alternation)
		if err != nil {
			return nil, nil, err
		}
		elemi = appendNodes(elemi, emptyNode)
		elemo = appendNodes(elemo, emptyNode)
		return elemi, elemo, nil

	case ElemGroup:
		return m.altGraph(v.Alternation)
	case ElemProseVal:
		return nil, nil, errors.New("prose value is not supported in transition graphs")
	}

	panic("unsupported element")
}

func newNode(elem ElemItf) *Node {
	id, _ := uuid.GenerateUUID()
	return &Node{
		ID:   id,
		Elem: elem,
		// Final node, no need to pipe I/O
	}
}

// ToMermaid produces a mermaid-encoded representation of the transition graph.
func (tg *TransitionGraph) ToMermaid() string {
	// Map all nodes
	mp := map[string]*Node{}
	for _, node := range tg.Entrypoints {
		if node == emptyNode {
			continue
		}
		mapNodes(mp, node)
	}

	// Write them all
	str := "flowchart LR\n    classDef entrypoint fill:#479abf\n\n"
	for _, node := range mp {
		// Write down the node
		nodeStr := "    " + node.ID
		elemStr := elemToString(node.Elem)
		if slices.Contains(tg.Endpoints, node) {
			nodeStr += "(((\"" + elemStr + "\")))"
		} else {
			nodeStr += "[\"" + elemStr + "\"]"
		}
		str += nodeStr
		if slices.Contains(tg.Entrypoints, node) {
			str += ":::entrypoint"
		}
		str += "\n"

		// Write down its links
		for _, next := range node.Nexts {
			str += fmt.Sprintf("    %s --> %s\n", node.ID, next.ID)
		}
		str += "\n"
	}

	// Don't forget the empty node
	if slices.Contains(tg.Entrypoints, emptyNode) {
		str += "    emptyNode(((\u2205))):::entrypoint\n"
	}

	return str
}

func mapNodes(mp map[string]*Node, node *Node) {
	if _, ok := mp[node.ID]; ok {
		return
	}
	mp[node.ID] = node
	for _, next := range node.Nexts {
		mapNodes(mp, next)
	}
}

func elemToString(elem ElemItf) string {
	switch v := elem.(type) {
	case ElemRulename:
		return v.Name
	case ElemCharVal:
		str := ""
		for _, b := range v.Values {
			if b == '`' {
				str += "backquote"
			} else if b == '"' {
				str += "dquote"
			} else if 33 <= b && b <= 127 {
				str += string(b)
			}
		}
		return str
	case ElemNumVal:
		if v.Status == StatRange {
			return fmt.Sprintf("0%s%s-%s", v.Base, v.Elems[0], v.Elems[1])
		}
		return fmt.Sprintf("0%s%s", v.Base, strings.Join(v.Elems, "."))
	}
	panic("not implemented yet")
}
