package goabnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_GetRule(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Rulename   string
		Rulemap    map[string]*Rule
		ExpectRule bool
	}{
		"core-rule": {
			Rulename:   "WSP",
			Rulemap:    ABNF.Rulemap,
			ExpectRule: true,
		},
		"rulemap-rule": {
			Rulename:   "rulelist",
			Rulemap:    ABNF.Rulemap,
			ExpectRule: true,
		},
		"case-insensitive": {
			Rulename:   "wsp",
			Rulemap:    ABNF.Rulemap,
			ExpectRule: true,
		},
		"unexisting-rule": {
			Rulename:   "im-n07-4-rul3",
			Rulemap:    ABNF.Rulemap,
			ExpectRule: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			rule := GetRule(tt.Rulename, tt.Rulemap)

			if tt.ExpectRule {
				assert.NotNil(rule)
			} else {
				assert.Nil(rule)
			}
		})
	}
}
