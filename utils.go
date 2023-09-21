package goabnf

import "strings"

// atob converts str to byte given the base.
func atob(str, base string) byte {
	switch base {
	case "B", "b":
		return bintob(str)
	case "D", "d":
		return dectob(str)
	case "X", "x":
		return hextob(str)
	}
	panic("invalid base")
}

func bintob(str string) byte {
	if len(str) > 8 { // 8 = log(base, sizeof(byte)*8), base=2
		panic("too large bin value")
	}
	out := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		cv := 0
		switch c {
		case '0':
			cv = 0
		case '1':
			cv = 1
		default:
			panic("invalid bit: " + string(c))
		}
		out += cv * pow(2, len(str)-i-1)
	}
	return byte(out)
}

func dectob(str string) byte {
	if len(str) > 3 { // 3 = log(base, sizeof(byte)*8), base=10
		panic("too large decimal value")
	}
	out := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		cv := 0
		switch c {
		case '0':
			cv = 0
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
		default:
			panic("invalid dec: " + string(c))
		}
		out += cv * pow(10, len(str)-i-1)
	}
	return byte(out)
}

func hextob(str string) byte {
	if len(str) > 8 { // 2 = log(base, sizeof(byte)*8), base=16
		panic("too large hex value")
	}
	out := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		cv := 0
		switch c {
		case '0':
			cv = 0
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
		default:
			panic("invalid hex: " + string(c))
		}
		out += cv * pow(16, len(str)-i-1)
	}
	return byte(out)
}

func pow(v, e int) int {
	if e == 0 {
		return 1
	}
	for i := 1; i < e; i++ {
		v *= v
	}
	return v
}

// getRule returns the rule by the given rulename, wether
// it is a core rule or present in the grammar, or nil if not found.
// It validates the RFC 5234 Section 2.1 "rule names are case insensitive".
func getRule(rulename string, rulemap map[string]*rule) *rule {
	for _, coreRule := range coreRules {
		if strings.EqualFold(rulename, coreRule.name) {
			return coreRule
		}
	}
	for _, rule := range rulemap {
		if strings.EqualFold(rulename, rule.name) {
			return rule
		}
	}
	return nil
}
