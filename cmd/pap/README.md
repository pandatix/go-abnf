# PandatiX's ABNF Parser

PandatiX's ABNF Parser is a CLI tool that provides a large API around ABNF.

 - [Installation](#installation)
 - [Commands](#commands)
   - [Validate](#validate)
   - [Generate](#generate)

## Installation

You can simply install it using `go install github.com/pandatix/go-abnf/cmd/pap@latest`.

## Commands

### Validate

Using subcommand `validate`, you can check an ABNF grammar is valid according to the RFC 5234 (with Errata 2968 and 3092) + RFC 7405.
Additionnaly, it proceeds to semantic validation of the grammar (see [the doc](https://pkg.go.dev/github.com/pandatix/go-abnf#SemvalABNF) for more info).

Here is an example use case that validates an ABNF grammar from stdin.

```bash
$ cat grammar.abnf | pap validate
```

It returns exit code 0 if the grammar is valid, else 1.

### Generate

Using subcommand `generate`, you can create a content from an ABNF grammar, using a random walk in the input grammmar.
It may be used as part of black/grey-box fuzzing from CLI (you may also use it in your Go app).

```bash
$ pap generate --input grammar.abnf --rulename rulelist

	
 	   ; Q>yY	Jp	C
	 	; @^G V$o
ks1-;	-
  	;!+X!p5e	
	 ; 	nllYyU	a%
 	;F  			
	  	 	
	=;&U( OM K6.6x,		 
 ; >u 
 
  [;}C	t 	` "zU	+(	p
 ;bW 3X 	}[ 
 	 
		
		 	 	69*5797509528326%b1011			;
	;;@  	#		v
 0"!& Qi "
	;|Hr	
 
 
	 
  	
				
 ;
			/[%xEA]/*<>/*(G)/8(%xFDABC2E.ECFA1BF8E.DE4ADDC.E.DBB4EADABBABFF.DC.6EBCBFAAAB.A5CFBEC79DCAE.6D48FECDF.CFEAFBEBDAEFCBCD.B.BCC.B.CBDFCBDAEBE.E3AAD2FB8FFEBCDE.FADFCDC6CAAFD3E)/*(95801443M)/*""/2558057670672%d555864801982/""];
;
Q=/<>;
e=/""
;
X=413[n]
;
q=*((""));
z=%d3698231.63304796242.337423.602230691381.72315740150.5304020.73390.1107.885716.5;
```
