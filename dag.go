package goabnf

type node struct {
	Rulename       string
	index, lowlink int
	onStack        bool
	Dependencies   []string
}

// Depgraph generates the
type Depgraph map[string]*node

// DependencyGraph creates a dependency graph
func (g *Grammar) DependencyGraph() Depgraph {
	graph := Depgraph{}
	for _, rule := range g.rulemap {
		graph[rule.name] = &node{
			Rulename:     rule.name,
			Dependencies: getDependencies(rule.alternation),
		}
	}
	return graph
}

func getDependencies(alt alternation) []string {
	deps := []string{}
	for _, conc := range alt.concatenations {
		for _, rep := range conc.repetitions {
			switch v := rep.element.(type) {
			case elemGroup:
				deps = appendDeps(deps, getDependencies(v.alternation)...)
			case elemOption:
				deps = appendDeps(deps, getDependencies(v.alternation)...)
			case elemRulename:
				deps = appendDeps(deps, v.name)
			}
		}
	}
	return deps
}

func appendDeps(deps []string, ndeps ...string) []string {
	for _, ndep := range ndeps {
		already := false
		for _, dep := range deps {
			if ndep == dep {
				already = true
				break
			}
		}
		if !already {
			deps = append(deps, ndep)
		}
	}
	return deps
}

// IsDag find Strongly Connected Components using Tarjan's algorithm
// and returns whether it contains cycle or not.
// Could be improved by Nuutila's or Pearce's algorithms, or replaced
// by Kosaraju's algorithm.
func (g *Grammar) IsDAG() bool {
	scc := &cycle{
		index: 0,
		stack: []*node{},
		dg:    g.DependencyGraph(),
	}
	scc.find()

	for _, sccs := range scc.sccs {
		if len(sccs) > 1 {
			return false
		}
	}
	return true
}

type cycle struct {
	index int
	stack []*node
	sccs  [][]*node

	dg Depgraph
}

func (c *cycle) find() {
	for _, v := range c.dg {
		if v.index == 0 {
			c.strongconnect(v)
		}
	}
}

func (c *cycle) strongconnect(v *node) {
	// Set the depth index for v to the smallest unused index
	v.index = c.index
	v.lowlink = c.index
	c.index++
	c.stack = append(c.stack, v)
	v.onStack = true

	// Consider successors of v
	for _, dep := range v.Dependencies {
		w, ok := c.dg[dep]
		if !ok {
			// core rules
			continue
		}
		if w.index == 0 {
			// Successor w has not yet been visited; recurse on it
			c.strongconnect(w)
			v.lowlink = min(v.lowlink, w.lowlink)
		} else {
			if w.onStack {
				// Successor w is in stack S and hence in the current SCC
				// If w is not on stack, then (v, w) is an edge pointing
				// to an SCC already found and must be ignored.
				v.lowlink = min(v.lowlink, w.index)
			}
		}
	}
	// If v is a root node, pop the stack and generate an SCC
	if v.lowlink == v.index {
		scc := []*node{}
		w := (*node)(nil)
		for w == nil || v.Rulename != w.Rulename {
			w = c.stack[len(c.stack)-1]
			c.stack = c.stack[:len(c.stack)-1]
			w.onStack = false
			scc = append(scc, w)
		}
		c.sccs = append(c.sccs, scc)
	}
}
