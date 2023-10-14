package commands

import (
	"fmt"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/urfave/cli/v2"
)

var Regex = &cli.Command{
	Name:        "regex",
	Usage:       "produce a regular expression from an ABNF grammar.",
	Description: "produce a regular expression from an ABNF grammar. It first validate the grammar (see `validate` command), then proceed to build a regex and write it to stdout.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "input",
			Usage: "set the input to get the ABNF grammar from. Set a file or let empty to read from stdin.",
			Value: "-",
		},
		&cli.StringFlag{
			Name:     "rulename",
			Usage:    "rulename to build the regex from from.",
			Required: true,
		},
	},
	Action: regex,
}

func regex(ctx *cli.Context) error {
	b, err := readInput(ctx)
	if err != nil {
		return err
	}

	// Build grammar
	g, err := goabnf.ParseABNF(b)
	if err != nil {
		return err
	}

	// Generate regex
	out, err := g.Regex(ctx.String("rulename"))
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", out)
	return nil
}
