package goabnf

import "strings"

// GetRule returns the rule by the given rulename, whether
// it is a core rule or present in the grammar, or nil if not found.
// It validates the RFC 5234 Section 2.1 "rule names are case insensitive".
func GetRule(rulename string, rulemap map[string]*Rule) *Rule {
	if rule := getRuleIn(rulename, coreRules); rule != nil {
		return rule
	}
	return getRuleIn(rulename, rulemap)
}

func getRuleIn(rulename string, rulemap map[string]*Rule) *Rule {
	for _, rule := range rulemap {
		if strings.EqualFold(rulename, rule.Name) {
			return rule
		}
	}
	return nil
}
