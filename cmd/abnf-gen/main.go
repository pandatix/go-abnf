// Command abnf-gen generates a standalone, specialised Go parser from an ABNF
// grammar file. It is designed to be driven by `go generate`:
//
//	//go:generate go run github.com/pandatix/go-abnf/cmd/abnf-gen -in grammar.abnf -root rulelist -pkg myparser -out parser_gen.go
//
// The emitted file depends only on the standard library and exposes Parse,
// Result (Valid/NumTrees/Ambiguous/Tree/Elements) and ParseTree. Because the
// generated identifiers (Parse, Result, ...) are package-scoped, generate at
// most one parser per package: put the directive and the output file in their
// own (sub)package, e.g. internal/myparser/.
package main

import (
	"flag"
	"fmt"
	"os"

	goabnf "github.com/pandatix/go-abnf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "abnf-gen:", err)
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", "", "input ABNF grammar file (required)")
	out := flag.String("out", "-", `output Go file, or "-" for stdout`)
	root := flag.String("root", "", "root rule the parser starts from (required)")
	pkg := flag.String("pkg", "", "package name for the generated file (required)")
	noValidate := flag.Bool("no-validate", false, "skip semantic validation of the grammar")
	flag.Parse()

	missing := func(name, val string) error {
		if val == "" {
			return fmt.Errorf("-%s is required", name)
		}
		return nil
	}
	for _, e := range []error{missing("in", *in), missing("root", *root), missing("pkg", *pkg)} {
		if e != nil {
			flag.Usage()
			return e
		}
	}

	src, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read %s: %w", *in, err)
	}

	var opts []goabnf.ABNFOption
	if *noValidate {
		opts = append(opts, goabnf.WithValidation(false))
	}
	code, err := goabnf.GenerateGoParserFromABNF(src, *root, *pkg, opts...)
	if err != nil {
		return err
	}

	if *out == "-" {
		_, err = os.Stdout.Write(code)
		return err
	}
	if err := os.WriteFile(*out, code, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "abnf-gen: wrote %s (%d bytes) for root %q\n", *out, len(code), *root)
	return nil
}
