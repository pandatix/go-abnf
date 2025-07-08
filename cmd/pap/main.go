package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pandatix/go-abnf/cmd/pap/commands"
	"github.com/urfave/cli/v2"
)

var (
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func main() {
	app := &cli.App{
		Name:  "PandatiX's ABNF Parser (PAP)",
		Usage: "CLI tool that provide a large API around ABNF.",
		Commands: []*cli.Command{
			commands.Validate,
			commands.Generate,
			commands.TransitionGraph,
			commands.Regex,
		},
		Flags: []cli.Flag{
			cli.VersionFlag,
			cli.HelpFlag,
		},
		Authors: []*cli.Author{
			{
				Name:  "Lucas Tesson - PandatiX",
				Email: "lucatesson@protonmail.com",
			},
		},
		Version: version,
		Metadata: map[string]any{
			"version": version,
			"commit":  commit,
			"date":    date,
			"builtBy": builtBy,
		},
	}

	// Setup stop signals
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		signal.Stop(sigs)
		cancel() // Triggers the <-ctx.Done() in the following goroutine
	}()
	go func() {
		select {
		case <-sigs:
			cancel()
			os.Exit(1)
		case <-ctx.Done():
			return
		}
	}()

	if err := app.RunContext(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}
