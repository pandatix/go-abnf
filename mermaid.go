package goabnf

import "fmt"

type MermaidDoc struct {
	nodes []graphNode
	links []any // TODO find ASAP how to handle this
}

func (doc *MermaidDoc) String() (str string) {
	// Init document
	str = "graph LR;\n"

	// Build nodes declaration
	str += "\t%% Nodes declaration\n"
	for _, node := range doc.nodes {
		// Setup label
		label := node.label
		if node.final {
			label += " end"
		}
		// Select node style
		if node.entry {
			// Rhombus
			str += fmt.Sprintf("\t%s{%s}\n", node.label, label) // TODO improve id for explainability
		} else {
			// Circle
			str += fmt.Sprintf("\t%s((%s))\n", node.label, label) // TODO improve id for explainability
		}
	}

	// Build links
	str += "\n\t%% Links\n"

	return
}

type graphNode struct {
	entry bool
	final bool
	label string
}

func ToMermaid(rule rule) *MermaidDoc {
	doc := &MermaidDoc{}
	alternationToMermaid(rule.alternation, doc)
	return doc
}

func alternationToMermaid(alt alternation, doc *MermaidDoc) {
	for _, concat := range alt.concatenations {
		for _, rep := range concat.repetitions {
			switch t := rep.element.(type) {
			case elemRulename:
				doc.nodes = append(doc.nodes, graphNode{
					entry: false, // TODO improve
					final: false, // TODO improve
					label: t.name,
				})

			case elemGroup:
				alternationToMermaid(t.alternation, doc)

			case elemOption:
				alternationToMermaid(t.alternation, doc)

			case elemCharVal:
				label := ""
				for _, v := range t.values {
					label += string(v)
				}
				doc.nodes = append(doc.nodes, graphNode{
					entry: false, // TODO improve
					final: false, // TODO improve
					label: label,
				})

			case elemNumVal:
				label := "%" + t.base
				if t.status == statRange {
					label += t.elems[0] + "-" + t.elems[1]
				} else {
					for _, e := range t.elems {
						label += e + "."
					}
				}
				doc.nodes = append(doc.nodes, graphNode{
					entry: false, // TOOD improve
					final: false, // TODO improve
					label: label,
				})

			case elemProseVal:
				label := "<"
				for _, v := range t.values {
					label += v
				}
				label += ">"
				doc.nodes = append(doc.nodes, graphNode{
					entry: false, // TODO improve
					final: false, // TODO improve
					label: label,
				})
			}
		}
	}
}
