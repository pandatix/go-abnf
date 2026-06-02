package goabnf

import (
	"strconv"
	"unicode/utf8"
)

// recognize.go holds the engine behind (*Grammar).IsValid.
//
// Validity only needs the SET of input positions each element can reach, never
// the (possibly exponential) set of distinct parse trees that reach them. We
// compute, for each (element, start-index), the set of reachable end-indices,
// deduplicating positions at every step and memoizing per (element, index).
// Positions live in [0, len(input)], so the work is polynomial rather than the
// exponential path enumeration that Parse performs.
//
// IsValid enforces left-termination before calling in, so the in-progress
// guard below is defense-in-depth: it can never fire for a left-terminating
// grammar (a same-index re-entry implies the rule is not left terminating).

type recognizer struct {
	g          *Grammar
	input      []byte
	memo       map[string]map[int]bool // element.String()+"@"+index -> reachable end set
	inProgress map[string]bool
}

func cloneSet(s map[int]bool) map[int]bool {
	out := make(map[int]bool, len(s))
	for k := range s {
		out[k] = true
	}
	return out
}

func (r *recognizer) reachAlt(alt Alternation, index int) map[int]bool {
	out := map[int]bool{}
	for _, c := range alt.Concatenations {
		for e := range r.reachConcat(c, index) {
			out[e] = true
		}
	}
	return out
}

func (r *recognizer) reachConcat(c Concatenation, index int) map[int]bool {
	cur := map[int]bool{index: true}
	for _, rep := range c.Repetitions {
		next := map[int]bool{}
		for p := range cur {
			for e := range r.reachRep(rep, p) {
				next[e] = true
			}
		}
		cur = next
		if len(cur) == 0 {
			break
		}
	}
	return cur
}

func (r *recognizer) reachRep(rep Repetition, index int) map[int]bool {
	ends := map[int]bool{}
	if rep.Min == 0 {
		ends[index] = true
	}

	// level = positions reachable after exactly c occurrences.
	level := map[int]bool{index: true}
	// Each *progressing* occurrence consumes >=1 byte, so positions strictly
	// grow until they stabilise; len(input)+2 iterations bound that, with a
	// couple extra to settle zero-width (nullable) elements.
	cap := len(r.input) + 2
	for c := 1; c <= cap; c++ {
		if rep.Max != inf && c > rep.Max {
			break
		}
		next := map[int]bool{}
		for p := range level {
			for e := range r.reachElem(rep.Element, p) {
				next[e] = true
			}
		}
		if len(next) == 0 {
			break
		}
		if c >= rep.Min {
			for e := range next {
				ends[e] = true
			}
		}
		// Fixpoint: nullable element whose position set stopped growing.
		stable := len(next) == len(level)
		if stable {
			for e := range next {
				if !level[e] {
					stable = false
					break
				}
			}
		}
		level = next
		if stable {
			// All larger counts (incl. any c >= Min) reach the same set.
			if rep.Min <= rep.Max || rep.Max == inf {
				for e := range level {
					ends[e] = true
				}
			}
			break
		}
	}
	return ends
}

func (r *recognizer) reachElem(elem ElemItf, index int) map[int]bool {
	key := elem.String() + "@" + strconv.Itoa(index)
	if cached, ok := r.memo[key]; ok {
		return cached
	}
	if r.inProgress[key] {
		// Re-entry at the same position == non-progressing recursion. Return
		// empty (sound under left-termination) instead of looping forever.
		return map[int]bool{}
	}
	r.inProgress[key] = true
	out := r.computeElem(elem, index)
	delete(r.inProgress, key)
	r.memo[key] = cloneSet(out)
	return out
}

func (r *recognizer) computeElem(elem ElemItf, index int) map[int]bool {
	out := map[int]bool{}
	switch v := elem.(type) {
	case ElemRulename:
		rule := GetRule(v.Name, r.g.Rulemap)
		if rule == nil {
			return out
		}
		return r.reachAlt(rule.Alternation, index)

	case ElemGroup:
		return r.reachAlt(v.Alternation, index)

	case ElemOption:
		out[index] = true // 0 occurrences
		for e := range r.reachAlt(v.Alternation, index) {
			out[e] = true
		}
		return out

	case ElemProseVal:
		// prose-val can't be matched (same as the original parser)
		return out

	case ElemNumVal:
		switch v.Status {
		case StatRange:
			if index >= len(r.input) {
				return out
			}
			min, max := numvalToRune(v.Elems[0], v.Base), numvalToRune(v.Elems[1], v.Base)
			ru, size := utf8.DecodeRune(r.input[index:])
			if ru == utf8.RuneError && size == 1 {
				return out
			}
			if min <= ru && ru <= max {
				out[index+size] = true
			}
		case StatSeries:
			idx := index
			for i := 0; i < len(v.Elems); i++ {
				s := string(numvalToRune(v.Elems[i], v.Base))
				sz := len([]byte(s))
				if idx+sz > len(r.input) || s != string(r.input[idx:idx+sz]) {
					return out
				}
				idx += sz
			}
			out[idx] = true
		}
		return out

	case ElemCharVal:
		idx := index
		for i := 0; i < len(v.Values); i++ {
			if idx >= len(r.input) {
				return out
			}
			ru, size := utf8.DecodeRune(r.input[idx:])
			if ru == utf8.RuneError && size == 1 {
				return out
			}
			if !sensequal(v.Values[i], ru, v.Sensitive) {
				return out
			}
			idx += size
		}
		out[idx] = true
		return out
	}
	return out
}
