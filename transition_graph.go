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
	grammar *Grammar
	options *tgoptions

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
// TODO it is possible to build transition graph out of cylic rules iff	it is not concatenated to another repetition (can't pipe O->I as there is no O). For instance, `a = "a" a` can exist.
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
		grammar:     g,
		options:     options,
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

func (tg *TransitionGraph) Reader() *TransitionGraphReader {
	return &TransitionGraphReader{
		tg:     tg,
		thread: []threadTuple{},
	}
}

type TransitionGraphReader struct {
	// tg is the transition graph to read from.
	tg *TransitionGraph

	// thread is the current travel path through tg.
	thread []threadTuple
}

type threadTuple struct {
	// node id
	id string

	// next node position in slice
	pos int

	// terminal node position counter (used for charval/numval)
	// for charvals it is used as a mask to know whether to lower or upper a char
	tpos int32

	// total possible variations (used for charval/numval)
	vtotal int32

	// justCut defines if the previous iteration was a cut over the thread
	// for later iterations.
	// If true, no deepest travel should be performed on the endpoint node.
	justCut bool
}

func (tgr *TransitionGraphReader) Next() bool {
	// Select root entrypoints to start from
	idx := 0
	if len(tgr.thread) != 0 {
		// If already defined, go on with it
		idx = tgr.thread[0].pos
	}
	if idx == len(tgr.tg.Entrypoints) {
		return false
	}

	// produce iff rules are deflated if necessary
	node := tgr.tg.Entrypoints[idx]
	return tgr.tg.options.deflateRules || canProduce(node, map[string]struct{}{})
}

func (tgr *TransitionGraphReader) Scan() []byte {
	// Select root entrypoints to start from
	idx := 0
	if len(tgr.thread) != 0 {
		// If already defined, go on with it
		idx = tgr.thread[0].pos
	} else {
		// If the thread has not been started yet, create it
		tgr.thread = []threadTuple{{}} // add initial tuple
	}

	// Don't read out of bounds i.e. don't produce once traveled
	// through all the transition graph
	if idx == len(tgr.tg.Entrypoints) {
		return nil
	}

	// Select proper entrypoint
	n := tgr.tg.Entrypoints[idx]

	// If is the empty node, prepare to go to next entrypoint and
	// return an empty slice
	if n == emptyNode {
		tgr.thread[0].pos++
		return []byte{}
	}

	// Else it is a non-empty node, so recurse through the thread
	b, roll := tgr.produce(n, 1)
	if roll {
		tgr.thread[0].pos++
		tgr.thread = tgr.thread[:1]
	}
	return b
}

func (tgr *TransitionGraphReader) produce(node *Node, threadIndex int) (prod []byte, roll bool) {
	// produce iff rules are deflated and if necessary
	if !tgr.tg.options.deflateRules && !canProduce(node, map[string]struct{}{}) {
		return nil, false
	}

	isInThread := len(tgr.thread) > threadIndex
	isLast := len(node.Nexts) == 0
	isEndpoint := slices.Contains(tgr.tg.Endpoints, node)
	isFullyVariated := false
	tpos := int32(0)
	if isInThread {
		tpos = tgr.thread[threadIndex].tpos
	}
	vtotal := int32(0)

	// Produce this node content
	switch v := node.Elem.(type) {
	case ElemCharVal:
		prod = make([]byte, 0, len(v.Values))
		if v.Sensitive {
			// Produce this whole char value, no need to variate anything
			for _, val := range v.Values {
				prod = append(prod, string(val)...)
			}
			vtotal++ // still count it else we won't know we "variated" it
		} else {
			// Copy each one and make it case-variant if necessary
			for i, r := range v.Values {
				isLower := r >= 'a' && r <= 'z'
				isUpper := r >= 'A' && r <= 'Z'
				variate := isLower || isUpper

				// Count all possible variations
				vtotal++
				if variate {
					vtotal++
				}

				// Write down
				if !variate {
					prod = append(prod, string(r)...)
				} else {
					// Compute lower and upper variants
					lower := r
					if isUpper {
						lower = lower - 'A' + 'a'
					}
					upper := r
					if isLower {
						upper = upper - 'a' + 'A'
					}

					// Append the good one in its spot
					if (tpos>>i)%2 == 1 {
						prod = append(prod, string(upper)...)
					} else {
						prod = append(prod, string(lower)...)
					}
				}
			}
		}

	case ElemNumVal:
		// We can't easily determine the number of bytes this numval will use,
		// at least len(v.Elems), at most 4*len(v.Elems) as Unicode code points can
		// take up to 4 bytes.

		switch v.Status {
		case StatSeries:
			for _, elem := range v.Elems {
				r := numvalToRune(elem, v.Base)
				prod = append(prod, []byte(string(r))...)
			}
			vtotal++ // still count it else we won't know we "variated" it

		case StatRange:
			min, max := numvalToInt32(v.Elems[0], v.Base), numvalToInt32(v.Elems[1], v.Base)
			dst := max - min + 1

			vtotal += dst // range of possibilities

			// Iteratively select one by one
			r := rune(min + tpos)
			prod = append(prod, []byte(string(r))...)
		}

	default:
		panic(fmt.Sprintf("should not happen, got type %v", v))
	}

	isFullyVariated = tpos+1 == vtotal // +1 <= we completed an iteration

	// Register in thread if not known yet
	if !isInThread {
		tgr.thread = append(tgr.thread, threadTuple{
			id:     node.ID,
			pos:    0,
			tpos:   tpos, // don't increase yet, will do it later if required
			vtotal: vtotal,
		})
	}

	// If has nothing next (is an endpoint), return fast
	// Stop here too if we are going to hit infinite recursions
	if isLast || !hasNextNode(node, tgr.thread[:threadIndex+1], tgr.thread[threadIndex].pos) {
		tgr.thread[threadIndex].tpos++ // btw we did an iteration :)
		roll = isFullyVariated
		return
	}

	// Else if the node is not the last in the travel but is an intermediary endpoint
	// that was not yet registered in the thread, we should stop there for now and wait
	// for the next iteration to go further.
	// Works too if we just cut it.
	if isEndpoint && (tgr.thread[threadIndex].justCut || !isInThread) {
		tgr.thread[threadIndex].justCut = false // reset it
		return
	}

	// From now on, the node is not the last in the travel.
	// If in the thread we take the next node ID.
	// Else (not yet in the thread) we add it.
	nid := 0
	if isInThread {
		nid = tgr.thread[threadIndex].pos
	} else {
		tgr.thread = append(tgr.thread, threadTuple{
			id:     node.ID,
			pos:    0,
			tpos:   tpos,
			vtotal: vtotal,
		})
	}

	// Select next node to produce on (one that is not already in the stack
	// -> avoid infinite recursions).
	nn := node.Nexts[nid]
	for {
		if !isInThread && transitionInThread(tgr.thread, node.ID, nn.ID) {
			nid++
			nn = node.Nexts[nid]
			continue
		}
		break
	}
	tgr.thread[threadIndex].pos = nid

	// Produce next node and concat to this one's result
	sub, roll := tgr.produce(nn, threadIndex+1)
	if roll {
		// If it is non fully variated yet, move onto next variation and cut down thread
		if !isFullyVariated {
			tgr.thread[threadIndex].tpos++          // this thread tuple needs to go on the next char
			tgr.thread[threadIndex].justCut = true  // hey future iteration, we just cut it so if you need to produce, go on
			tgr.thread = tgr.thread[:threadIndex+1] // cut thread from here to regen nexts
			return append(prod, sub...), false
		}

		// If there are no nexts, propagate roll
		if nid+1 == len(node.Nexts) {
			return append(prod, sub...), true
		}

		// Then if there is a non-processed (in stack) edge, roll on it, else propagate roll next
		var nextNotInThread *int
		for i := nid + 1; i < len(node.Nexts); i++ {
			if !transitionInThread(tgr.thread[:threadIndex+1], node.ID, node.Nexts[i].ID) {
				nextNotInThread = &i
				break
			}
		}
		if nextNotInThread != nil {
			tgr.thread = tgr.thread[:threadIndex+1]
			tgr.thread[threadIndex].pos = *nextNotInThread
			tgr.thread[threadIndex].tpos = 0
			tgr.thread[threadIndex].vtotal = 0

			return append(prod, sub...), false
		}
		return append(prod, sub...), isFullyVariated
	}
	return append(prod, sub...), roll
}

func transitionInThread(thread []threadTuple, from, to string) bool {
	for i, e := range thread {
		if e.id == from && i+1 != len(thread) && thread[i+1].id == to {
			return true
		}
	}
	return false
}

func hasNextNode(node *Node, thread []threadTuple, pos int) bool {
	rems := node.Nexts[pos:]
	for _, rem := range rems {
		if !transitionInThread(thread, node.ID, rem.ID) {
			return true
		}
	}
	return false
}

func canProduce(node *Node, done map[string]struct{}) bool {
	if node == emptyNode {
		done["empty"] = struct{}{}
		return true
	}
	done[node.ID] = struct{}{}
	if _, ok := node.Elem.(ElemRulename); ok {
		return false
	}
	for _, next := range node.Nexts {
		if _, ok := done[next.ID]; ok {
			continue
		}
		if !canProduce(next, done) {
			return false
		}
	}
	return true
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
			tgs, chi, cho := chainTransitionGraph(elemi, elemo, rep.Min)
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

	// recurse iff not known yet
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
		for _, r := range v.Values {
			isLower := r >= 'a' && r <= 'z'
			isUpper := r >= 'A' && r <= 'Z'
			requireBoth := (isLower || isUpper) && !v.Sensitive

			if !requireBoth {
				n := newNode(ElemCharVal{
					Sensitive: true,
					Values:    []rune{r},
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
				nlv := r
				if isUpper {
					nlv = strmin(nlv)
				}
				nuv := r
				if isLower {
					nuv = strmax(nuv)
				}

				nl := newNode(ElemCharVal{
					Sensitive: true,
					Values:    []rune{nlv},
				})
				nu := newNode(ElemCharVal{
					Sensitive: true,
					Values:    []rune{nuv},
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
			min, max := numvalToInt32(v.Elems[0], v.Base), numvalToInt32(v.Elems[1], v.Base)
			for i := min; i <= max; i++ {
				n := newNode(ElemNumVal{
					Base:   v.Base,
					Status: StatSeries,
					Elems:  []string{string(rune(i))},
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
