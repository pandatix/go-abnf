package goabnf

import (
	"bytes"
	"errors"
	"math/rand"
)

// Generate is an experimental feature that consumes a seed for
// a pseudo-random number generator, used to randomly travel through
// the grammar given a rulename to work on.
// With this, it provides reproducibility, usefull for fuzz crashers.
//
// You can leverage its capacities (maximum repetitions, length
// threshold, etc.) with the functional options.
//
// It is a good capability for testing and fuzzing parsers during
// testing, compliance, fuzzing or optimization.
func (g *Grammar) Generate(seed int64, rulename string, opts ...GenerateOption) ([]byte, error) {
	// TODO can get to crash if generation has only one path that can't end up such as "a=a\r\n"
	// Checking the rule is not cyclic is not sufficient (e.g. ABNF's alternation)
	// Must check this rule has the possibility to end

	// Use a pseudo-random number generator
	rand := rand.NewSource(seed)

	// Define conditions from options
	options := &genOpts{
		repMax:    16,
		threshold: 256,
	}
	for _, opt := range opts {
		opt.apply(options)
	}

	// Generate actual content
	rule := getRule(rulename, g.rulemap)
	if rule == nil {
		return nil, errors.New("rule is not part of the grammar or the core rules")
	}
	out := []byte{}
	generateAlt(rand, g, &out, rule.alternation, options)
	return out, nil
}

func generateAlt(rand rand.Source, g *Grammar, out *[]byte, alt alternation, options *genOpts) {
	// Select any possible path in the alternation
	cnt := alt.concatenations[int(rand.Int63())%len(alt.concatenations)]

	// Travel through all the repetitions
	for _, rep := range cnt.repetitions {
		repmax := rep.max
		if repmax == inf {
			repmax = options.repMax
		}
		torep := rep.min + int(rand.Int63())%(repmax-rep.min+1)
		for i := 0; generateKeepGoing(i, torep, rep.min, len(*out), options.threshold); i++ {
			switch elem := rep.element.(type) {
			case elemRulename:
				rule := getRule(elem.name, g.rulemap)
				generateAlt(rand, g, out, rule.alternation, options)

			case elemOption:
				if (rand.Int63() % 2) == 0 {
					generateAlt(rand, g, out, elem.alternation, options)
				}

			case elemGroup:
				generateAlt(rand, g, out, elem.alternation, options)

			case elemNumVal:
				switch elem.status {
				case statRange:
					min, max := atob(elem.elems[0], elem.base), atob(elem.elems[1], elem.base)
					appendPtr(out, min+byte(rand.Int63())%(max-min+1))

				case statSeries:
					for _, v := range elem.elems {
						appendPtr(out, atob(v, elem.base))
					}
				}

			case elemProseVal:
				panic("unable to generate prose val")

			case elemCharVal:
				for _, val := range elem.values {
					if elem.sensitive && (int(rand.Int63())%2) == 0 {
						val = bytes.ToUpper([]byte{val})[0]
					}
					appendPtr(out, val)
				}
			}
		}
	}
}

func appendPtr(slc *[]byte, v ...byte) {
	b := *slc
	b = append(b, v...)
	*slc = b
}

func generateKeepGoing(i, torep, minrep, lenout, threshold int) bool {
	// If can do no run and reached threshold, skip
	if i == 0 && minrep == 0 && lenout >= threshold {
		return false
	}
	return i < torep
}

// GenerateOption is an option for the *Grammar.Generate method.
type GenerateOption interface {
	apply(*genOpts)
}

type genOpts struct {
	repMax    int
	threshold int
}

type repMaxOption int

// WithRepMax defines the maximum repetition to stop generating at.
func WithRepMax(repMax int) repMaxOption {
	return repMaxOption(repMax)
}

func (opt repMaxOption) apply(opts *genOpts) {
	opts.repMax = int(opt)
}

type thresholdOption int

// WithThreshold defines the length threshold to stop generating at.
func WithThreshold(threshold int) thresholdOption {
	return thresholdOption(threshold)
}

func (opt thresholdOption) apply(opts *genOpts) {
	opts.threshold = int(opt)
}
