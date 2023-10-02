package commands

import (
	"fmt"

	goabnf "github.com/pandatix/go-abnf"
	"github.com/urfave/cli/v2"
)

var Validate = &cli.Command{
	Name:        "validate",
	Usage:       "validate an ABNF grammar.",
	Description: "validate an ABNF grammar from a file or stdin, and return its pretty print to stdout (exit code 0) or the error to stderr (exit code 1).",
	Flags: []cli.Flag{
		cli.HelpFlag,
		&cli.StringFlag{
			Name:  "input",
			Usage: "set the input to get the ABNF from. Set a file or let empty to read from stdin.",
			Value: "-",
		},
		&cli.BoolFlag{
			Name:  "sem-val",
			Usage: "set if proceed to semantic validation, see https://pkg.go.dev/github.com/pandatix/go-abnf#SemvalABNF for more info.",
			Value: true,
		},
	},
	Action: validate,
}

func validate(ctx *cli.Context) error {
	b, err := readInput(ctx)
	if err != nil {
		return err
	}

	// Validate ABNF input
	opts := []goabnf.ParseABNFOption{}
	if ctx.IsSet("sem-val") {
		opts = append(opts, goabnf.WithValidation(ctx.Bool("sem-val")))
	}
	g, err := goabnf.ParseABNF(b, opts...)
	if err != nil {
		return err
	}
	fmt.Println(g.PrettyPrint())

	return err
}
