<div align="center">
	<h1>Go-ABNF</h1>
	<a href="https://pkg.go.dev/github.com/pandatix/go-abnf"><img src="https://shields.io/badge/-reference-blue?logo=go&style=for-the-badge" alt="reference"></a>
	<a href="https://goreportcard.com/report/github.com/pandatix/go-abnf"><img src="https://goreportcard.com/badge/github.com/pandatix/go-abnf?style=for-the-badge" alt="go report"></a>
	<a href="https://coveralls.io/github/pandatix/go-abnf?branch=main"><img src="https://img.shields.io/coverallsCoverage/github/pandatix/go-abnf?style=for-the-badge" alt="Coverage Status"></a>
	<br>
	<a href=""><img src="https://img.shields.io/github/license/pandatix/go-abnf?style=for-the-badge" alt="License"></a>
	<a href="https://github.com/pandatix/go-abnf/actions?query=workflow%3Aci+"><img src="https://img.shields.io/github/actions/workflow/status/pandatix/go-abnf/ci.yaml?style=for-the-badge&label=CI" alt="CI"></a>
	<a href="https://github.com/pandatix/go-abnf/actions/workflows/codeql-analysis.yaml"><img src="https://img.shields.io/github/actions/workflow/status/pandatix/go-abnf/codeql-analysis.yaml?style=for-the-badge&label=CodeQL" alt="CodeQL"></a>
	<br>
	<a href="https://securityscorecards.dev/viewer/?uri=github.com/pandatix/go-abnf"><img src="https://img.shields.io/ossf-scorecard/github.com/pandatix/go-abnf?label=openssf%20scorecard&style=for-the-badge" alt="OpenSSF Scoreboard"></a>
	<a href="https://bestpractices.coreinfrastructure.org/en/projects/7840"><img src="https://img.shields.io/cii/summary/7840?style=for-the-badge&label=openssf%20best%20practices" alt="OpenSSF Best Practices Summary"></a>
</div>

Go module to handle Augmented Backus-Naur Form (ABNF), providing a large API.
It implements RFC 5234 and 7405, with Errata 2968 and 3076.

Capabilities:
 - [ ] parse ABNF (to manipulable datastructure ; with cycle detection)
 - [ ] compile ABNF to regex
 - [ ] create a minimal set of tests that covers the full grammar
 - [ ] generate a visual representation of the ABNF grammar provided
 - [ ] create an ABNF fuzzer for your modules (version >= Go1.18beta1)

## How it works
