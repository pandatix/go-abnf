module github.com/pandatix/go-abnf/cmd/pap

go 1.22.3

require (
	github.com/pandatix/go-abnf v0.0.0-00010101000000-000000000000
	github.com/urfave/cli/v2 v2.25.7
)

replace github.com/pandatix/go-abnf => ../..

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
)
