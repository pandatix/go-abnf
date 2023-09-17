package goabnf

type node struct {
	index, lowlink int
	onStack        bool
	dependencies   []string
}

type depgraph map[string]node

func genGraph(g *Grammar) depgraph {
	graph := depgraph{}
	for _, rule := range g.rulemap {
		graph[rule.name] = node{
			dependencies: getDependencies(rule.alternation),
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
				deps = append(deps, getDependencies(v.alternation)...)
			case elemOption:
				deps = append(deps, getDependencies(v.alternation)...)
			case elemRulename:
				deps = append(deps, v.name)
			}
		}
	}
	return deps
}

// Find Strongly Connected Components using Tarjan's algorithm
// Could be improved by Nuutila's or Pearce's algorithms, or replaced
// by Kosaraju's algorithm.
func isDAG(g *Grammar) bool {
	scc := &scc{
		index: 0,
		s:     []node{},
		dg:    genGraph(g),
	}
	scc.find()

	for _, sccs := range scc.sccs {
		if len(sccs) > 1 {
			return false
		}
	}
	return true
}

type scc struct {
	index int
	s     []node
	sccs  [][]node

	dg depgraph
}

func (scc *scc) find() {
	for _, v := range scc.dg {
		if v.index == 0 {
			scc.strongconnect(v)
		}
	}
}

func (scc *scc) strongconnect(v node) {
	// Set the depth index for v to the smallest unused index
	v.index = scc.index
	v.lowlink = scc.index
	scc.index++
	scc.s = append(scc.s, v)
	v.onStack = true

	// Consider successors of v
	// TODO complete
}
