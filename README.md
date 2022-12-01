# Go-ABNF

Go-ABNF is a Golang module providing an API to manipulate ABNF grammars according to [RFC 5234](https://datatracker.ietf.org/doc/html/rfc5234), giving you the ability to:
 - [ ] parse ABNF (to manipulable datastructure ; with cycle detection)
 - [ ] compile ABNF to regex
 - [ ] create a minimal set of tests that covers the full grammar
 - [ ] generate a visuale representation of the ABNF grammar provided
 - [ ] create an ABNF fuzzer for your modules (version >= Go1.18beta1)

Those functionalities are provided to CLI thanks to [abnf-toolbox](cmd/abnf-toolbox).

## How it works

### ABNF Turing completness

As ABNF is **Turing complete**, it could be defined using its own syntax, as it's proposed by the RFC in Appendix A.
Knowing this, you can use an ABNF definition to parse an input, and derive from the result another grammar.

For instance, let's take an ABNF grammar that defines an the IPv4 syntax.
This ABNF grammar is parsed by the core ABNF grammar to generate to IPv4 ABNF grammar.
The IPv4 ABNF grammar now parses a given input (let's say `192.168.1.80`).
Based on the ABNF definition of IPv4, we are now able to recuperate the interesting fields.

Notice that to be a Turing complete implementation, it must be able to parses iself, but needs a starting point.
This starting point is an hardcoded ABNF grammar.

From this last point, you can also understand that you are able to parse indefinitely the ABNF grammar using the ABNF grammar.

Finally, using the example, you can see that you are able to chain parsers.
For instance, you can start by parsing an EBNF grammar, and use this last grammar to parse the Go grammar. Then you can parse Go code, using ABNF.

### Oriented graph

Once you understood that the ABNF enables its own parsing, we can go on how to travel through an oriented graph.

First of all, we need to remind a few concepts.

TODO add oriented graph concepts explanation.

Now, we can represent the ABNF grammar using an oriented graph.
This enables us to visualize a bridge between the two, so we would be able to use properties of both.

TODO representation of ABNF grammar using oriented graph

Now, we'll standard oriented graph travel algorithm. Quick reminder that each node of our network consumes the given input.
For this we create a pool of workers, and assign a worker each possible path.
If a path is valid, create other workers if necessary. If not, drop this path from the possible ones.

The first complexity comes from the schemas.
The schemas describes a semantic different part of an oriented graph.
There are 4 schemas:
 - **Entry**, defining an entrypoint of a rule.
 - **Transfer**, when a node has a single outgoing path to the next node.
 - **Fan-out**, when a node has multiple outgoing paths to multiple nodes.
 - **Fan-in**, when a node has multiple ingoing paths from multiple nodes.
 - **Exit**, defining the termination of a rule.

Using those schemas, we can dissect complex ABNF rules.

TODO complex ABNF rule schema dissection


