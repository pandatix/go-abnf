package commands

import (
	"fmt"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/urfave/cli/v2"
)

var Generate = &cli.Command{
	Name:        "generate",
	Usage:       "generate a string from an ABNF grammar.",
	Description: "generate a string from an ABNF grammar. It first validate the grammar (see `validate` command), then proceed to random walk in the grammar graph, and write it to stdout.",
	Flags: []cli.Flag{
		cli.HelpFlag,
		&cli.StringFlag{
			Name:  "input",
			Usage: "set the input to get the ABNF grammar from. Set a file or let empty to read from stdin.",
			Value: "-",
		},
		&cli.StringFlag{
			Name:     "rulename",
			Usage:    "rulename to generate from.",
			Required: true,
		},
		&cli.Int64Flag{
			Name:  "seed",
			Usage: "define the seed that will be used by the random walk. If let empty, default to a random one. This value provides reproducibility thus can be saved for fuzzing purposes.",
		},
		&cli.IntFlag{
			Name:  "rep-max",
			Usage: "if set, define the maximum repetition to do in the random walk. This value affects reproducibility thus should be changed with caution.",
		},
		&cli.IntFlag{
			Name:  "threshold",
			Usage: "if set, define the deepness threshold to do in the random walk. This value affects reproducibility thus should be changed with caution.",
		},
	},
	Action: generate,
}

func generate(ctx *cli.Context) error {
	b, err := readInput(ctx)
	if err != nil {
		return err
	}

	// Build grammar
	g, err := goabnf.ParseABNF(b)
	if err != nil {
		return err
	}

	// Generate content
	opts := []goabnf.GenerateOption{}
	if ctx.IsSet("rep-max") {
		opts = append(opts, goabnf.WithRepMax(ctx.Int("rep-max")))
	}
	if ctx.IsSet("threshold") {
		opts = append(opts, goabnf.WithThreshold(ctx.Int("threshold")))
	}
	out, err := g.Generate(findSeed(ctx), ctx.String("rulename"), opts...)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", out)
	return nil
}
