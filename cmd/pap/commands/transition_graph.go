package commands

import (
	"fmt"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/urfave/cli/v2"
)

var TransitionGraph = &cli.Command{
	Name:        "transition-graph",
	Usage:       "produce a mermaid representation of a transition graph, from an ABNF grammar.",
	Description: "produce a mermaid representation of a transition graph, from an ABNF grammar. It first validate the grammar (see `validate` command) then produce the mermaid flowchart and write it to stdout.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "input",
			Usage: "set the input to get the ABNF grammar from. Set a file or let empty to read from stdin.",
			Value: "-",
		},
		&cli.StringFlag{
			Name:     "rulename",
			Usage:    "rulename to start from.",
			Required: true,
		},
		&cli.BoolFlag{
			Name: "deflate-rules",
		},
		&cli.BoolFlag{
			Name: "deflate-charvals",
		},
		&cli.BoolFlag{
			Name: "deflate-numvals",
		},
		&cli.IntFlag{
			Name: "repetition-threshold",
		},
	},
	Action: transitionGraph,
}

func transitionGraph(ctx *cli.Context) error {
	b, err := readInput(ctx)
	if err != nil {
		return err
	}

	// Build grammar
	g, err := goabnf.ParseABNF(b)
	if err != nil {
		return err
	}

	// Build options
	opts := []goabnf.TGOption{}
	if ctx.IsSet("deflate-rules") {
		opts = append(opts, goabnf.WithDeflateRules(true))
	}
	if ctx.IsSet("deflate-charvals") {
		opts = append(opts, goabnf.WithDeflateCharVals(true))
	}
	if ctx.IsSet("deflate-numvals") {
		opts = append(opts, goabnf.WithDeflateNumVals(true))
	}
	if ctx.IsSet("repetition-threshold") {
		opts = append(opts, goabnf.WithRepetitionThreshold(ctx.Int("repetition-threshold")))
	}

	// Generate transition graph
	tg, err := g.TransitionGraph(ctx.String("rulename"), opts...)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", tg.ToMermaid())
	return nil
}
