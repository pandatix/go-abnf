package goabnf

import "fmt"

// Mermaid returns a flowchart of the dependency graph.
func (dg *Depgraph) Mermaid() string {
	out := "flowchart TD\n"
	for _, node := range *dg {
		for _, dep := range node.Dependencies {
			out += fmt.Sprintf("\t%s --> %s\n", node.Rulename, dep)
		}
		out += "\n"
	}
	return out
}
