package goabnf

import (
	"fmt"
	"strconv"
	"strings"
)

type elemItf interface {
	fmt.Stringer
}

type rule struct {
	name        string
	alternation alternation
}

func (rl rule) String() string {
	return fmt.Sprintf("%s = %s", rl.name, rl.alternation)
}

type alternation struct {
	concatenations []concatenation
}

func (alt alternation) String() string {
	str := ""
	for _, concat := range alt.concatenations {
		str += fmt.Sprintf("%s / ", concat)
	}
	return strings.TrimSuffix(str, " / ")
}

type concatenation struct {
	repetitions []repetition
}

func (cnt concatenation) String() string {
	str := ""
	for _, rep := range cnt.repetitions {
		str += fmt.Sprintf("%s ", rep)
	}
	return strings.TrimSuffix(str, " ")
}

type repetition struct {
	min, max int
	element  elemItf
}

func (rep repetition) String() string {
	if rep.min == rep.max {
		if rep.min == 1 {
			return rep.element.String()
		}
		return strconv.Itoa(rep.min) + rep.element.String()
	}
	str := ""
	if rep.min != 0 {
		str += strconv.Itoa(rep.min)
	}
	str += "*"
	if rep.max != inf {
		str += strconv.Itoa(rep.max)
	}
	return str + rep.element.String()
}

type elemRulename struct {
	name string
}

func (erln elemRulename) String() string {
	return erln.name
}

var _ elemItf = (*elemRulename)(nil)

type elemGroup struct {
	alternation alternation
}

func (egrp elemGroup) String() string {
	return "(" + egrp.alternation.String() + ")"
}

var _ elemItf = (*elemGroup)(nil)

type elemOption struct {
	alternation alternation
}

func (eopt elemOption) String() string {
	return "[" + eopt.alternation.String() + "]"
}

var _ elemItf = (*elemOption)(nil)

type elemCharVal struct {
	// sensitive is by default false, added for support with RFC 7405
	sensitive bool
	values    []byte
}

func (ecvl elemCharVal) String() string {
	str := ""
	for _, val := range ecvl.values {
		str += string(val)
	}
	return `"` + str + `"`
}

var _ elemItf = (*elemCharVal)(nil)

//   - `status` is `statSeries`: `elems` contains all the expected
//     values in the order of the grammar defined them ;
//   - `status` is `statRange`: `elems` contains the start and end
//     bounds (so no more than two).
type elemNumVal struct {
	base   string
	status status
	elems  []string
}

func (envl elemNumVal) String() string {
	str := "%" + envl.base
	spl := "."
	if envl.status == statRange {
		spl = "-"
	}
	for _, val := range envl.elems {
		str += val + spl
	}
	return strings.TrimSuffix(str, spl)
}

var _ elemItf = (*elemNumVal)(nil)

type elemProseVal struct {
	values []string
}

func (epvl elemProseVal) String() string {
	str := ""
	for _, val := range epvl.values {
		str += val
	}
	return "<" + str + ">"
}

var _ elemItf = (*elemProseVal)(nil)

type status int

const (
	statSeries status = iota
	statRange
)
