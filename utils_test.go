package goabnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_Atob(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Str         string
		Base        string
		ExpectedVal byte
	}{
		"hex": {
			Str:         "3c",
			Base:        "x",
			ExpectedVal: 0x3c,
		},
		"binary": {
			Str:         "10",
			Base:        "b",
			ExpectedVal: 0b10,
		},
		"decimal": {
			Str:         "56",
			Base:        "d",
			ExpectedVal: 56,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			val := atob(tt.Str, tt.Base)

			assert.Equal(tt.ExpectedVal, val)
		})
	}
}

func Test_U_GetRule(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Rulename   string
		Rulemap    map[string]*rule
		ExpectRule bool
	}{
		"core-rule": {
			Rulename:   "WSP",
			Rulemap:    ABNF.rulemap,
			ExpectRule: true,
		},
		"rulemap-rule": {
			Rulename:   "rulelist",
			Rulemap:    ABNF.rulemap,
			ExpectRule: true,
		},
		"case-insensitive": {
			Rulename:   "wsp",
			Rulemap:    ABNF.rulemap,
			ExpectRule: true,
		},
		"unexisting-rule": {
			Rulename:   "im-n07-4-rul3",
			Rulemap:    ABNF.rulemap,
			ExpectRule: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			rule := getRule(tt.Rulename, tt.Rulemap)

			if tt.ExpectRule {
				assert.NotNil(rule)
			} else {
				assert.Nil(rule)
			}
		})
	}
}
