package main

import (
	"fmt"

	goabnf "github.com/pandatix/go-abnf"
)

var input = []byte(`char = WSP`)

func main() {
	g, err := goabnf.ParseABNF(input)
	fmt.Printf("g: %v\n", g)
	fmt.Printf("err: %v\n", err)
}
