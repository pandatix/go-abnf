package goabnf

import (
	"errors"
	"fmt"
)

var (
	// ErrNoSolutionFound is an error returned when parsing an ABNF
	// grammar and no solution has been found.
	ErrNoSolutionFound = errors.New("no solution found, input ABNF grammar may be invalid")
)

type ErrMultipleSolutionsFound struct {
	Paths []*Path
}

var _ error = (*ErrMultipleSolutionsFound)(nil)

func (err ErrMultipleSolutionsFound) Error() string {
	return "multiple solutions found, this should not happen. Please open an issue. This could eventually need an Erratum from IETF tracking"
}

// ErrRuleNotFound is an error returned when the rule was not found
// as part of the grammar.
type ErrRuleNotFound struct {
	Rulename string
}

var _ error = (*ErrRuleNotFound)(nil)

func (err ErrRuleNotFound) Error() string {
	return fmt.Sprintf("rule %s was not found in grammar", err.Rulename)
}

// ErrDependencyNotFound is an error returned during ABNF grammar
// semantic vaildation, if a rule depends on an unexisting rule.
type ErrDependencyNotFound struct {
	Rulename string
}

var _ error = (*ErrDependencyNotFound)(nil)

func (err ErrDependencyNotFound) Error() string {
	return fmt.Sprintf("unsatisfied dependency (rule) %s", err.Rulename)
}

// ErrSemanticRepetition is an error returned during ABNF grammar
// semantic validation, if a repetition has min < max.
type ErrSemanticRepetition struct {
	Repetition Repetition
}

var _ error = (*ErrSemanticRepetition)(nil)

func (err ErrSemanticRepetition) Error() string {
	return fmt.Sprintf("invalid semantic of input ABNF grammar for repetition %s", err.Repetition)
}

// ErrDuplicatedRule is an error returned when the rule already
// exist as part of the grammar.
type ErrDuplicatedRule struct {
	Rulename string
}

var _ error = (*ErrDuplicatedRule)(nil)

func (err ErrDuplicatedRule) Error() string {
	return fmt.Sprintf("rule %s was already defined in grammar", err.Rulename)
}

// ErrCyclicRule is an error returned when can't work due to an
// unavoidable cyclic rule.
type ErrCyclicRule struct {
	Rulename string
}

var _ error = (*ErrCyclicRule)(nil)

func (err ErrCyclicRule) Error() string {
	return fmt.Sprintf("can't generate a content as the rule %s involves an unavoidable cycle", err.Rulename)
}
