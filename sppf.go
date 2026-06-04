package goabnf

import (
	"math/big"
	"strconv"
	"unicode/utf8"
)

// This file implements a GLL parser (Scott & Johnstone) producing a binarized
// Shared Packed Parse Forest (SPPF) for ABNF grammars.
//
// GLL parses ANY context-free grammar -- including left, right, hidden and
// mutual recursion, and arbitrary ambiguity -- in worst-case O(n^3) time and
// space, using a graph-structured stack (GSS) and a descriptor worklist whose
// "seen" set makes recursion terminate. The forest shares every sub-derivation
// and packs ambiguity, so it stays polynomial even when it represents
// exponentially or infinitely many trees.
//
// Pipeline: lower the ABNF AST into a flat slotted grammar (synthetic
// nonterminals for groups, options and repetitions), then run GLL over the
// slots. Recognition, ambiguity, tree counting and extraction are polynomial
// queries over the resulting forest.

// ---------------------------------------------------------------------------
// Slotted grammar
// ---------------------------------------------------------------------------

type symKind uint8

const (
	symNonterm symKind = iota
	symTerm            // a char-val / num-val / prose-val matcher
	symEps             // matches the empty string
)

type ssym struct {
	kind symKind
	nt   int     // nonterminal id, for symNonterm
	term ElemItf // terminal element, for symTerm
}

type sgNT struct {
	label    string   // diagnostic label
	isRule   bool     // corresponds to an original ABNF rule (kept in the tree)
	ruleName string   // original rule name when isRule
	alts     [][]ssym // alternates; every alternate has >= 1 symbol
}

type slotGrammar struct {
	nts   []*sgNT
	index map[string]int // dedup key -> nt id
	start int
}

func (sg *slotGrammar) reserve(key, label string) (int, bool) {
	if id, ok := sg.index[key]; ok {
		return id, true
	}
	id := len(sg.nts)
	sg.nts = append(sg.nts, &sgNT{label: label})
	sg.index[key] = id
	return id, false
}

// compileSlots lowers grammar starting at rootRulename into a slotted grammar.
const defaultMaxSlots = 1 << 16

func compileSlots(g *Grammar, rootRulename string, maxSlots int) (*slotGrammar, error) {
	if GetRule(rootRulename, g.Rulemap) == nil {
		return nil, &ErrRuleNotFound{Rulename: rootRulename}
	}
	sg := &slotGrammar{index: map[string]int{}}
	c := &lowerer{g: g, sg: sg, max: maxSlots}
	sg.start = c.rule(rootRulename)
	if c.err != nil {
		return nil, c.err
	}
	if c.over {
		return nil, &ErrGrammarTooLarge{Max: maxSlots}
	}
	return sg, nil
}

type lowerer struct {
	g    *Grammar
	sg   *slotGrammar
	err  error
	max  int  // max nonterminals; 0 == unbounded
	over bool // budget exceeded
}

func (c *lowerer) budgetExceeded() bool {
	if c.max > 0 && len(c.sg.nts) >= c.max {
		c.over = true
	}
	return c.over
}

func (c *lowerer) rule(name string) int {
	key := "rule:" + canon(name)
	id, existed := c.sg.reserve(key, name)
	if existed {
		return id
	}
	rule := GetRule(name, c.g.Rulemap)
	if rule == nil {
		// Unknown rule: a nonterminal with no alternates derives nothing.
		c.sg.nts[id].label = name
		return id
	}
	c.sg.nts[id].isRule = true
	c.sg.nts[id].ruleName = rule.Name
	c.sg.nts[id].alts = c.alts(rule.Alternation)
	return id
}

func (c *lowerer) alts(a Alternation) [][]ssym {
	out := make([][]ssym, 0, len(a.Concatenations))
	for _, cc := range a.Concatenations {
		seq := make([]ssym, 0, len(cc.Repetitions))
		for _, rep := range cc.Repetitions {
			seq = append(seq, c.rep(rep))
		}
		if len(seq) == 0 {
			seq = []ssym{{kind: symEps}}
		}
		out = append(out, seq)
	}
	return out
}

func (c *lowerer) rep(rep Repetition) ssym {
	if rep.Min == 1 && rep.Max == 1 {
		return c.elem(rep.Element)
	}
	key := "rep:" + rep.String()
	id, existed := c.sg.reserve(key, rep.String())
	if existed {
		return ssym{kind: symNonterm, nt: id}
	}
	// A malformed bound where max < min accepts nothing: leave the rep
	// nonterminal with no alternates so it derives the empty language (it is
	// unsatisfiable, NOT unbounded). This matches the recognizer.
	if rep.Max != inf && rep.Max < rep.Min {
		return ssym{kind: symNonterm, nt: id}
	}
	esym := c.elem(rep.Element)
	var k int // number of optional occurrences; -1 == unbounded
	if rep.Max == inf {
		k = -1
	} else {
		k = rep.Max - rep.Min
	}
	tail := c.optTail(esym, k)
	// Prepend `Min` required occurrences as a chain ending in the tail.
	head := tail
	for n := 0; n < rep.Min; n++ {
		if c.budgetExceeded() {
			break
		}
		head = c.reqOne(esym, head)
	}
	// Point the rep nonterminal at the head's alternates.
	c.sg.nts[id].alts = c.sg.nts[head].alts
	c.sg.nts[id].label = rep.String()
	return ssym{kind: symNonterm, nt: id}
}

// optTail builds `T ::= eps | E T` (unbounded) or the bounded chain.
// optTail builds the optional/unbounded tail of a repetition without deep
// recursion. Unbounded (k<0) is a single self-referential nonterminal
// T ::= eps | E T. Bounded (k>=0) is the chain O_0 ::= eps,
// O_j ::= eps | E O_(j-1), built iteratively so a huge finite bound is limited
// by the slot budget instead of overflowing the Go stack.
func (c *lowerer) optTail(esym ssym, k int) int {
	base := "opttail:" + symKey(esym) + "|"
	if id, ok := c.sg.index[base+strconv.Itoa(k)]; ok {
		return id
	}
	if k < 0 {
		id, _ := c.sg.reserve(base+"-1", "opt*")
		c.sg.nts[id].alts = [][]ssym{
			{{kind: symEps}},
			{esym, {kind: symNonterm, nt: id}},
		}
		return id
	}
	prev, _ := c.sg.reserve(base+"0", "opt0")
	c.sg.nts[prev].alts = [][]ssym{{{kind: symEps}}}
	for j := 1; j <= k; j++ {
		if c.budgetExceeded() {
			return prev
		}
		jid, existed := c.sg.reserve(base+strconv.Itoa(j), "optj")
		if existed {
			prev = jid
			continue
		}
		c.sg.nts[jid].alts = [][]ssym{
			{{kind: symEps}},
			{esym, {kind: symNonterm, nt: prev}},
		}
		prev = jid
	}
	return prev
}

// reqOne builds `R ::= E next`.
func (c *lowerer) reqOne(esym ssym, next int) int {
	key := "req:" + symKey(esym) + "|" + strconv.Itoa(next)
	id, existed := c.sg.reserve(key, "req")
	if existed {
		return id
	}
	c.sg.nts[id].alts = [][]ssym{{esym, {kind: symNonterm, nt: next}}}
	return id
}

func (c *lowerer) elem(e ElemItf) ssym {
	switch v := e.(type) {
	case ElemRulename:
		return ssym{kind: symNonterm, nt: c.rule(v.Name)}
	case ElemGroup:
		return ssym{kind: symNonterm, nt: c.group(v)}
	case ElemOption:
		return ssym{kind: symNonterm, nt: c.option(v)}
	case ElemCharVal, ElemNumVal, ElemProseVal:
		return ssym{kind: symTerm, term: e}
	}
	return ssym{kind: symTerm, term: e}
}

func (c *lowerer) group(v ElemGroup) int {
	key := "grp:" + v.String()
	id, existed := c.sg.reserve(key, v.String())
	if existed {
		return id
	}
	c.sg.nts[id].alts = c.alts(v.Alternation)
	return id
}

func (c *lowerer) option(v ElemOption) int {
	key := "opt:" + v.String()
	id, existed := c.sg.reserve(key, v.String())
	if existed {
		return id
	}
	alts := [][]ssym{{{kind: symEps}}}
	alts = append(alts, c.alts(v.Alternation)...)
	c.sg.nts[id].alts = alts
	return id
}

func symKey(s ssym) string {
	switch s.kind {
	case symNonterm:
		return "n" + strconv.Itoa(s.nt)
	case symEps:
		return "e"
	default:
		return "t" + s.term.String()
	}
}

func canon(name string) string {
	b := []byte(name)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// SPPF nodes
// ---------------------------------------------------------------------------

type gnodeKind uint8

const (
	gSymbol gnodeKind = iota // a nonterminal node (Start..End)
	gInter                   // a binarisation intermediate node
	gTerm                    // a terminal / epsilon node
)

type gnode struct {
	kind       gnodeKind
	nt         int // symbol nonterminal id, for gSymbol
	Start, End int
	packs      [][]*gnode // each pack has 1 or 2 children; >1 pack == ambiguity
}

func (n *gnode) addPack(children []*gnode) {
	for _, p := range n.packs {
		if len(p) != len(children) {
			continue
		}
		same := true
		for i := range p {
			if p[i] != children[i] {
				same = false
				break
			}
		}
		if same {
			return
		}
	}
	n.packs = append(n.packs, children)
}

// ---------------------------------------------------------------------------
// GLL machinery
// ---------------------------------------------------------------------------

type slot struct{ nt, alt, dot int }

type gssNode struct {
	ret     slot // return slot
	pos     int
	edges   []gssEdge
	edgeSet map[gssEdge]bool
}

type gssEdge struct {
	w  *gnode
	to *gssNode
}

type descriptor struct {
	L slot
	u *gssNode
	i int
	w *gnode
}

type gllParser struct {
	sg    *slotGrammar
	input []byte

	nodes  map[nodeKey]*gnode
	gss    map[gssKey]*gssNode
	u0     *gssNode
	seen   map[descriptor]bool
	work   []descriptor
	popped map[*gssNode]map[*gnode]bool

	maxNodes int
	aborted  bool
}

// nodeKey interns SPPF nodes without allocating strings. Distinct kinds never
// collide: symbol nodes key on (kind,nt,start,end); intermediate nodes on
// (kind,L,start,end); terminal nodes on (kind,start,end).
type nodeKey struct {
	kind       gnodeKind
	nt         int
	L          slot
	start, end int
}

type gssKey struct {
	ret slot
	pos int
}

func (p *gllParser) add(L slot, u *gssNode, i int, w *gnode) {
	d := descriptor{L, u, i, w}
	if p.seen[d] {
		return
	}
	p.seen[d] = true
	p.work = append(p.work, d)
}

func (p *gllParser) gssNodeFor(ret slot, pos int) *gssNode {
	k := gssKey{ret, pos}
	if v, ok := p.gss[k]; ok {
		return v
	}
	v := &gssNode{ret: ret, pos: pos, edgeSet: map[gssEdge]bool{}}
	p.gss[k] = v
	return v
}

func (p *gllParser) create(L slot, u *gssNode, i int, w *gnode) *gssNode {
	v := p.gssNodeFor(L, i)
	e := gssEdge{w: w, to: u}
	if !v.edgeSet[e] {
		v.edgeSet[e] = true
		v.edges = append(v.edges, e)
		for z := range p.popped[v] {
			y := p.getNodeP(L, w, z)
			p.add(L, u, z.End, y)
		}
	}
	return v
}

func (p *gllParser) pop(u *gssNode, i int, z *gnode) {
	if u == p.u0 {
		return
	}
	if p.popped[u] == nil {
		p.popped[u] = map[*gnode]bool{}
	}
	p.popped[u][z] = true
	for _, e := range u.edges {
		y := p.getNodeP(u.ret, e.w, z)
		p.add(u.ret, e.to, i, y)
	}
}

func (p *gllParser) findNode(k nodeKey) *gnode {
	if v, ok := p.nodes[k]; ok {
		return v
	}
	if p.maxNodes > 0 && len(p.nodes) >= p.maxNodes {
		p.aborted = true
	}
	v := &gnode{kind: k.kind, nt: k.nt, Start: k.start, End: k.end}
	p.nodes[k] = v
	return v
}

func (p *gllParser) getNodeT(start, end int) *gnode {
	return p.findNode(nodeKey{kind: gTerm, nt: -1, start: start, end: end})
}

// getNodeP combines left node w (may be nil == $) and right node z under slot L.
func (p *gllParser) getNodeP(L slot, w, z *gnode) *gnode {
	prod := p.sg.nts[L.nt].alts[L.alt]
	betaEmpty := L.dot == len(prod)
	if L.dot == 1 && !betaEmpty {
		return z // single symbol consumed, more to come: pass straight up
	}
	start := z.Start
	if w != nil {
		start = w.Start
	}
	var k nodeKey
	if betaEmpty {
		k = nodeKey{kind: gSymbol, nt: L.nt, start: start, end: z.End}
	} else {
		k = nodeKey{kind: gInter, nt: -1, L: L, start: start, end: z.End}
	}
	y := p.findNode(k)
	if w != nil {
		y.addPack([]*gnode{w, z})
	} else {
		y.addPack([]*gnode{z})
	}
	return y
}

// matchTerm returns the end index after matching the terminal at i, or -1.
func (p *gllParser) matchTerm(s ssym, i int) int {
	if s.kind == symEps {
		return i
	}
	switch v := s.term.(type) {
	case ElemCharVal:
		idx := i
		for k := 0; k < len(v.Values); k++ {
			if idx >= len(p.input) {
				return -1
			}
			r, size := utf8.DecodeRune(p.input[idx:])
			if r == utf8.RuneError && size == 1 {
				return -1
			}
			if !sensequal(v.Values[k], r, v.Sensitive) {
				return -1
			}
			idx += size
		}
		return idx
	case ElemNumVal:
		switch v.Status {
		case StatRange:
			if i >= len(p.input) {
				return -1
			}
			min, ok1 := numvalToRuneOK(v.Elems[0], v.Base)
			max, ok2 := numvalToRuneOK(v.Elems[1], v.Base)
			if !ok1 || !ok2 {
				return -1
			}
			r, size := utf8.DecodeRune(p.input[i:])
			if r == utf8.RuneError && size == 1 {
				return -1
			}
			if min <= r && r <= max {
				return i + size
			}
			return -1
		case StatSeries:
			idx := i
			for k := 0; k < len(v.Elems); k++ {
				ru, ok := numvalToRuneOK(v.Elems[k], v.Base)
				if !ok {
					return -1
				}
				str := string(ru)
				sz := len(str)
				if idx+sz > len(p.input) || str != string(p.input[idx:idx+sz]) {
					return -1
				}
				idx += sz
			}
			return idx
		}
	}
	return -1 // prose-val and anything else never matches
}

// parse runs the GLL loop and returns the symbol node (start, 0, n) or nil.
func (p *gllParser) parse() *gnode {
	startNT := p.sg.start
	p.u0 = &gssNode{ret: slot{-1, -1, -1}, pos: 0}
	for ai := range p.sg.nts[startNT].alts {
		p.add(slot{startNT, ai, 0}, p.u0, 0, nil)
	}
	for len(p.work) > 0 {
		if p.aborted {
			return nil
		}
		d := p.work[len(p.work)-1]
		p.work = p.work[:len(p.work)-1]
		p.process(d)
	}
	key := nodeKey{kind: gSymbol, nt: startNT, start: 0, end: len(p.input)}
	return p.nodes[key]
}

func (p *gllParser) process(d descriptor) {
	L, u, i, w := d.L, d.u, d.i, d.w
	for {
		prod := p.sg.nts[L.nt].alts[L.alt]
		if L.dot == len(prod) {
			z := w
			if z == nil {
				z = p.getNodeT(i, i)
			}
			p.pop(u, i, z)
			return
		}
		s := prod[L.dot]
		if s.kind == symNonterm {
			ret := slot{L.nt, L.alt, L.dot + 1}
			v := p.create(ret, u, i, w)
			for ai := range p.sg.nts[s.nt].alts {
				p.add(slot{s.nt, ai, 0}, v, i, nil)
			}
			return
		}
		j := p.matchTerm(s, i)
		if j < 0 {
			return
		}
		cR := p.getNodeT(i, j)
		next := slot{L.nt, L.alt, L.dot + 1}
		w = p.getNodeP(next, w, cR)
		i = j
		L = next
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Forest is a shared packed parse forest produced by ParseForest.
type Forest struct {
	sg       *slotGrammar
	input    []byte
	rulename string
	root     *gnode
	built    int
}

// ForestOption configures ParseForest.
type ForestOption func(*forestConfig)

type forestConfig struct {
	maxNodes int
	maxSlots int
}

// WithMaxForestNodes bounds the number of SPPF nodes the forest may allocate.
// Because a complete SPPF is worst-case cubic in the input length, this caps the
// time and memory ParseForest can spend on adversarial input. 0 means unbounded.
func WithMaxForestNodes(n int) ForestOption { return func(c *forestConfig) { c.maxNodes = n } }

// WithMaxSlots bounds the number of nonterminals produced while lowering the
// grammar. A finite repetition m*n lowers to ~n nonterminals, so this caps the
// cost of an adversarial grammar such as a = 9999999999"x". 0 means unbounded;
// the default is 65536.
func WithMaxSlots(n int) ForestOption { return func(c *forestConfig) { c.maxSlots = n } }

// ErrForestTooLarge is returned by ParseForest when the SPPF exceeds the
// configured WithMaxForestNodes budget.
type ErrForestTooLarge struct{ Max int }

func (e *ErrForestTooLarge) Error() string {
	return "abnf: parse forest exceeded " + strconv.Itoa(e.Max) + " nodes"
}

// ErrGrammarTooLarge is returned by ParseForest when lowering the grammar would
// exceed the WithMaxSlots budget, typically because of an absurd repetition
// bound (e.g. a = 9999999999"x").
type ErrGrammarTooLarge struct{ Max int }

func (e *ErrGrammarTooLarge) Error() string {
	return "abnf: grammar lowering exceeded " + strconv.Itoa(e.Max) + " nonterminals"
}

// ParseForest parses input with grammar starting at rootRulename using GLL,
// returning the shared packed parse forest. It runs in worst-case O(n^3) time
// and space for ANY grammar -- left/right/mutual recursion and ambiguity
// included -- so it is safe on untrusted or malformed grammars.
func ParseForest(input []byte, grammar *Grammar, rootRulename string, opts ...ForestOption) (*Forest, error) {
	cfg := forestConfig{maxSlots: defaultMaxSlots}
	for _, o := range opts {
		o(&cfg)
	}
	sg, err := compileSlots(grammar, rootRulename, cfg.maxSlots)
	if err != nil {
		return nil, err
	}
	p := &gllParser{
		sg:       sg,
		input:    input,
		nodes:    map[nodeKey]*gnode{},
		gss:      map[gssKey]*gssNode{},
		seen:     map[descriptor]bool{},
		popped:   map[*gssNode]map[*gnode]bool{},
		maxNodes: cfg.maxNodes,
	}
	root := p.parse()
	if p.aborted {
		return nil, &ErrForestTooLarge{Max: cfg.maxNodes}
	}
	return &Forest{sg: sg, input: input, rulename: rootRulename, root: root, built: len(p.nodes)}, nil
}

// Valid reports whether the whole input is derivable by the root rule.
func (f *Forest) Valid() bool { return f.root != nil }

// Nodes returns the number of forest nodes reachable from the root.
func (f *Forest) Nodes() int {
	if f.root == nil {
		return 0
	}
	seen := map[*gnode]bool{}
	var walk func(n *gnode)
	walk = func(n *gnode) {
		if seen[n] {
			return
		}
		seen[n] = true
		for _, pk := range n.packs {
			for _, c := range pk {
				walk(c)
			}
		}
	}
	walk(f.root)
	return len(seen)
}

// Ambiguous reports whether the input has more than one distinct parse tree.
func (f *Forest) Ambiguous() bool {
	if f.root == nil {
		return false
	}
	seen := map[*gnode]bool{}
	var walk func(n *gnode) bool
	walk = func(n *gnode) bool {
		if seen[n] {
			return false
		}
		seen[n] = true
		if len(n.packs) > 1 {
			return true
		}
		for _, pk := range n.packs {
			for _, c := range pk {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(f.root)
}

// NumTrees returns the number of distinct parse trees the forest represents.
// A result of -1 means infinitely many (a cycle in the forest, i.e. an
// infinitely-ambiguous grammar such as A = A / "x").
func (f *Forest) NumTrees() *big.Int {
	if f.root == nil {
		return big.NewInt(0)
	}
	memo := map[*gnode]*big.Int{}
	onStack := map[*gnode]bool{}
	infinite := false
	var count func(n *gnode) *big.Int
	count = func(n *gnode) *big.Int {
		if v, ok := memo[n]; ok {
			return v
		}
		if onStack[n] {
			infinite = true
			return big.NewInt(1)
		}
		onStack[n] = true
		total := big.NewInt(0)
		if len(n.packs) == 0 {
			total = big.NewInt(1)
		}
		for _, pk := range n.packs {
			prod := big.NewInt(1)
			for _, c := range pk {
				prod.Mul(prod, count(c))
			}
			total.Add(total, prod)
		}
		onStack[n] = false
		memo[n] = total
		return total
	}
	res := count(f.root)
	if infinite {
		return big.NewInt(-1)
	}
	return res
}

// ParseTree is a concrete syntax tree keyed by grammar rules: rule nodes carry
// the rule name, terminals are leaves with empty Rule.
type ParseTree struct {
	Rule       string
	Start, End int
	Children   []*ParseTree
}

// Tree extracts a single parse tree (first packing at each node), or nil if the
// input is invalid. A visited guard keeps extraction finite on cyclic forests.
func (f *Forest) Tree() *ParseTree {
	if f.root == nil {
		return nil
	}
	return f.emitSymbol(f.root, map[*gnode]bool{})
}

func (f *Forest) emitSymbol(n *gnode, onStack map[*gnode]bool) *ParseTree {
	t := &ParseTree{Start: n.Start, End: n.End}
	if n.kind == gSymbol && n.nt >= 0 && f.sg.nts[n.nt].isRule {
		t.Rule = f.sg.nts[n.nt].ruleName
	}
	onStack[n] = true
	f.collect(n, &t.Children, onStack)
	delete(onStack, n)
	return t
}

func (f *Forest) collect(n *gnode, into *[]*ParseTree, onStack map[*gnode]bool) {
	if len(n.packs) == 0 {
		if n.kind == gTerm && n.End > n.Start {
			*into = append(*into, &ParseTree{Start: n.Start, End: n.End})
		}
		return
	}
	for _, c := range n.packs[0] {
		f.collectChild(c, into, onStack)
	}
}

func (f *Forest) collectChild(c *gnode, into *[]*ParseTree, onStack map[*gnode]bool) {
	switch {
	case c.kind == gTerm:
		if c.End > c.Start {
			*into = append(*into, &ParseTree{Start: c.Start, End: c.End})
		}
	case c.kind == gSymbol && c.nt >= 0 && f.sg.nts[c.nt].isRule:
		if onStack[c] {
			*into = append(*into, &ParseTree{Rule: f.sg.nts[c.nt].ruleName, Start: c.Start, End: c.End})
			return
		}
		*into = append(*into, f.emitSymbol(c, onStack))
	default:
		if onStack[c] {
			return
		}
		onStack[c] = true
		f.collect(c, into, onStack)
		delete(onStack, c)
	}
}
