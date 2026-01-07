package goabnf

import (
	"strings"
)

// numvalToRune converts a numeric value given its base into the corresponding rune.
func numvalToRune(str, base string) rune {
	if err := checkBounds(str, base); err != nil {
		panic(err)
	}
	return rune(numvalToInt32(str, base))
}

func numvalToInt32(str, base string) (out int32) {
	if err := checkBounds(str, base); err != nil {
		panic(err)
	}

	str = strings.TrimLeft(str, "0")
	switch base {
	case "B", "b":
		out = binToInt32(str)

	case "D", "d":
		out = decToInt32(str)

	case "X", "x":
		out = hexToInt32(str)
	}
	return
}

func binToInt32(str string) (out int32) {
	for i := 0; i < len(str); i++ {
		cv := 0
		if str[i] == '1' {
			cv = 1
		}
		out += int32(cv * pow(2, len(str)-i-1))
	}
	return
}

func decToInt32(str string) (out int32) {
	for i := 0; i < len(str); i++ {
		cv := 0
		switch str[i] {
		case '1':
			cv = 1
		case '2':
			cv = 2
		case '3':
			cv = 3
		case '4':
			cv = 4
		case '5':
			cv = 5
		case '6':
			cv = 6
		case '7':
			cv = 7
		case '8':
			cv = 8
		case '9':
			cv = 9
		}
		out += int32(cv * pow(10, len(str)-i-1))
	}
	return
}

func hexToInt32(str string) (out int32) {
	for i := 0; i < len(str); i++ {
		cv := 0
		switch str[i] {
		case '1':
			cv = 1
		case '2':
			cv = 2
		case '3':
			cv = 3
		case '4':
			cv = 4
		case '5':
			cv = 5
		case '6':
			cv = 6
		case '7':
			cv = 7
		case '8':
			cv = 8
		case '9':
			cv = 9
		case 'A', 'a':
			cv = 10
		case 'B', 'b':
			cv = 11
		case 'C', 'c':
			cv = 12
		case 'D', 'd':
			cv = 13
		case 'E', 'e':
			cv = 14
		case 'F', 'f':
			cv = 15
		}
		out += int32(cv * pow(16, len(str)-i-1))
	}
	return
}

// returns v^e
func pow(v, e int) int {
	if e == 0 {
		return 1
	}
	result := v
	for i := 1; i < e; i++ {
		result *= v
	}
	return result
}

func checkBounds(str, base string) error {
	str = strings.TrimLeft(str, "0")
	switch base {
	// Whatever the base, the higher value we arbitrary decide to support is
	// the maximal Unicode character i.e. U+10FFFF.
	//
	// Every value (represented as integer) is then in interval [0;1_114_111].
	// For each base, we can compute the number of characters of an acceptable
	// num-val as ceil(log(base,1_114_111)).
	//
	// We also have to ensure that it does not go over the boundaries even if
	// of an acceptable length, e.g., 0xFFFFFF is not.

	case "B", "b":
		// 21 = ceil(log(2, max_unicode))
		// U+10FFFF = Ob100001111111111111111
		if len(str) > 21 ||
			(len(str) == 21 && (str[1] != '0' || str[2] != '0' || str[3] != '0' || str[4] != '0')) {
			return &ErrTooLargeNumeral{
				Base:  base,
				Value: str,
			}
		}

	case "D", "d":
		// 7 = ceil(log(10, max_unicode))
		// U+10FFFF = 0d1114111
		if len(str) > 7 ||
			(len(str) == 7 && (str[0] > '1' || (str[0] == '1' && (str[1] > '1' || (str[1] == '1' && (str[2] > '1' || (str[2] == '1' && (str[3] > '4' || (str[3] == '4' && (str[4] > '1' || (str[4] == '1' && (str[5] > '1' || (str[5] == '1' && str[6] > '1'))))))))))))) {
			return &ErrTooLargeNumeral{
				Base:  base,
				Value: str,
			}
		}

	case "X", "x":
		// 6 = ceil(log(16, max_unicode))
		// U+10FFFF = 0x10FFFF
		if len(str) > 6 ||
			(len(str) == 6 && (str[0] > '1' || (str[0] == '1' && (str[1] > '0')))) {
			return &ErrTooLargeNumeral{
				Base:  base,
				Value: str,
			}
		}
	}

	return nil
}

// GetRule returns the rule by the given rulename, whether
// it is a core rule or present in the grammar, or nil if not found.
// It validates the RFC 5234 Section 2.1 "rule names are case insensitive".
func GetRule(rulename string, rulemap map[string]*Rule) *Rule {
	// First look in the newly defined rules, as we could override definitions
	if rule := getRuleIn(rulename, rulemap); rule != nil {
		return rule
	}
	return getRuleIn(rulename, coreRules)
}

func getRuleIn(rulename string, rulemap map[string]*Rule) *Rule {
	for _, rule := range rulemap {
		if strings.EqualFold(rulename, rule.Name) {
			return rule
		}
	}
	return nil
}
