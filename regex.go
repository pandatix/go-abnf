package goabnf

import (
	"fmt"
	"regexp"
	"strings"
)

// Regex builds a regex that validates the given rulename.
//
// It imply that the rulename does not contain any cycle in its
// dependency graph as it would not be able to compile it.
//
// Notice it produces non-optimised regular expressions, such that
// it is easy to produce a better-performing one by hand.
func (g *Grammar) Regex(rulename string) (string, error) {
	// Check can generate safely i.e. no infinite recursino
	isCyclic, err := g.RuleContainsCycle(rulename)
	if err != nil {
		return "", err
	}
	if isCyclic {
		return "", &ErrCyclicRule{
			Rulename: rulename,
		}
	}

	rule := GetRule(rulename, g.Rulemap)
	return rule.regex(g)
}

func (r Rule) regex(g *Grammar) (string, error) {
	return r.Alternation.regex(g)
}

func (alt Alternation) regex(g *Grammar) (string, error) {
	str := "("
	for _, cnt := range alt.Concatenations {
		reg, err := cnt.regex(g)
		if err != nil {
			return "", err
		}
		str += reg + "|"
	}
	return strings.TrimRight(str, "|") + ")", nil
}

func (cnt Concatenation) regex(g *Grammar) (string, error) {
	str := ""
	for _, rep := range cnt.Repetitions {
		reg, err := rep.regex(g)
		if err != nil {
			return "", err
		}
		str += "(" + reg + ")"
	}
	return str, nil
}

func (rep Repetition) regex(g *Grammar) (string, error) {
	reps := ""
	switch {
	case rep.Min == rep.Max:
		reps = fmt.Sprintf("{%d}", rep.Min)
	case rep.Min == 0:
		if rep.Max == inf {
			reps = "*"
		} else {
			reps = fmt.Sprintf("{,%d}", rep.Max)
		}
	case rep.Max == inf:
		reps = fmt.Sprintf("{%d,}", rep.Min)
	}
	reg, err := rep.Element.regex(g)
	if err != nil {
		return "", err
	}
	str := "(" + reg + ")" + reps + ""
	return str, nil
}

func (e ElemRulename) regex(g *Grammar) (string, error) {
	rule := GetRule(e.Name, g.Rulemap)
	return rule.regex(g)
}

func (e ElemGroup) regex(g *Grammar) (string, error) {
	reg, err := e.Alternation.regex(g)
	if err != nil {
		return "", err
	}
	return "(" + reg + ")", nil
}

func (e ElemOption) regex(g *Grammar) (string, error) {
	reg, err := e.Alternation.regex(g)
	if err != nil {
		return "", err
	}
	return "(" + reg + ")?", nil
}

func (e ElemProseVal) regex(g *Grammar) (string, error) {
	return "", ErrHandlingProseVal
}

func (e ElemNumVal) regex(g *Grammar) (string, error) {
	// XXX what if the chars are out of printable characters ? (still in unicode)

	reg := ""
	switch e.Status {
	case StatRange:
		min, max := numvalToInt32(e.Elems[0], e.Base), numvalToInt32(e.Elems[1], e.Base)
		reg += regescape(rune(min)) + "-" + regescape(rune(max))

	case StatSeries:
		for _, s := range e.Elems {
			bts := numvalToRune(s, e.Base)
			rs := []rune(string(bts))
			for _, r := range rs {
				reg += regescape(r)
			}
		}
	}
	return "[" + reg + "]", nil
}

func (e ElemCharVal) regex(g *Grammar) (string, error) {
	str := ""
	for _, b := range e.Values {
		str += regescape(b)
	}
	return str, nil
}

func regescape(r rune) string {
	return regexp.QuoteMeta(string(r))
}
