package commands

import (
	"crypto/rand"
	"io"
	"os"

	"github.com/urfave/cli/v2"
)

func readInput(ctx *cli.Context) ([]byte, error) {
	input := ctx.String("input")
	if input == "-" {
		// Load from stdin if input is "-" (default)
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(input)
}

func findSeed(ctx *cli.Context) int64 {
	if ctx.IsSet("seed") {
		return ctx.Int64("seed")
	}

	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return int64(b[0])
}
