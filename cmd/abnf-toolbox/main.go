package main

import (
	"fmt"
	"io"
	"log"
	"os"

	abnf "github.com/pandatix/go-abnf"
)

func main() {
	// Open ABNF sample
	f, err := os.Open("/media/lucas/HDD-U/Documents/go-abnf/samples/NIST-IR_7695_Figure5-1.abnf")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", b)

	// Parse it
	_, err = abnf.ParseABNF(b)
	if err != nil {
		log.Fatal(err)
	}
}
