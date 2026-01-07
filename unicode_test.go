package goabnf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_U_Unicode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		Grammar  *Grammar
		Expected []byte
	}{
		"a": {
			// This unicode character is encoded on 1 byte
			Grammar:  mustGrammar("a=%x61\r\n"),
			Expected: []byte("a"),
		},
		"pi": {
			// This unicode character is encoded on 2 bytes
			Grammar:  mustGrammar("a=%x03c0\r\n"),
			Expected: []byte("π"), // U+03C0
		},
		"snowman": {
			// This unicode character is encoded on 3 bytes
			Grammar:  mustGrammar("a=%x2603\r\n"),
			Expected: []byte("☃"), // U+2603
		},
		"4-bytes": {
			// This unicode character is encoded on 4 bytes
			Grammar:  mustGrammar("a=%x1F973\r\n"),
			Expected: []byte("🥳"), // U+1F973
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			valid, err := tt.Grammar.IsValid("a", tt.Expected)
			require.True(t, valid)
			require.NoError(t, err)

			out, err := tt.Grammar.Generate(0, "a")
			require.Equal(t, string(tt.Expected), string(out))
			require.NoError(t, err)
		})
	}
}
