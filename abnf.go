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

func (this rule) String() string {
	return fmt.Sprintf("%s = %s", this.name, this.alternation)
}

type alternation struct {
	concatenations []concatenation
}

func (this alternation) String() string {
	str := ""
	for _, concat := range this.concatenations {
		str += fmt.Sprintf("%s / ", concat)
	}
	return strings.TrimSuffix(str, " / ")
}

type concatenation struct {
	repetitions []repetition
}

func (this concatenation) String() string {
	str := ""
	for _, rep := range this.repetitions {
		str += fmt.Sprintf("%s ", rep)
	}
	return strings.TrimSuffix(str, " ")
}

type repetition struct {
	min, max int
	element  elemItf
}

func (this repetition) String() string {
	if this.min == this.max {
		if this.min == 1 {
			return this.element.String()
		}
		return strconv.Itoa(this.min) + this.element.String()
	}
	str := ""
	if this.min != 0 {
		str += strconv.Itoa(this.min)
	}
	str += "*"
	if this.max != inf {
		str += strconv.Itoa(this.max)
	}
	return str + this.element.String()
}

type elemRulename struct {
	name string
}

func (this elemRulename) String() string {
	return this.name
}

var _ elemItf = (*elemRulename)(nil)

type elemGroup struct {
	alternation alternation
}

func (this elemGroup) String() string {
	return "(" + this.alternation.String() + ")"
}

var _ elemItf = (*elemGroup)(nil)

type elemOption struct {
	alternation alternation
}

func (this elemOption) String() string {
	return "[" + this.alternation.String() + "]"
}

var _ elemItf = (*elemOption)(nil)

type elemCharVal struct {
	values []rune
}

func (this elemCharVal) String() string {
	str := ""
	for _, val := range this.values {
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

func (this elemNumVal) String() string {
	str := "%" + this.base
	spl := "."
	if this.status == statRange {
		spl = "-"
	}
	for _, val := range this.elems {
		str += val + spl
	}
	return strings.TrimSuffix(str, spl)
}

var _ elemItf = (*elemNumVal)(nil)

type elemProseVal struct {
	values []string
}

func (this elemProseVal) String() string {
	str := ""
	for _, val := range this.values {
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
