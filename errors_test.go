package goabnf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_U_ParseError_Position pins the furthest-failure diagnostics: a malformed
// grammar yields a *ParseError locating where parsing stalled, while still
// matching the historical ErrNoSolutionFound sentinel via errors.Is.
func Test_U_ParseError_Position(t *testing.T) {
	// Missing trailing CRLF: the parser reaches the end of `"x"` and expects,
	// among others, a CR. This is the classic ABNF authoring mistake.
	_, err := ParseABNF([]byte(`a = "x"`))
	require.Error(t, err)

	assert.True(t, errors.Is(err, ErrNoSolutionFound), "must still match the sentinel")

	var pe *ParseError
	require.True(t, errors.As(err, &pe), "must be a *ParseError")
	assert.Equal(t, 1, pe.Line)
	assert.Equal(t, 7, pe.Offset) // just past `a = "x"`
	assert.Equal(t, 8, pe.Col)
	assert.NotEmpty(t, pe.Expected)

	// Error on a later line is located on that line.
	_, err = ParseABNF([]byte("a = \"x\"\r\nb = \"y\"\r\nc = = \r\n"))
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, 3, pe.Line, "error reported on line 3")
}

// Test_U_ParseError_BareLF pins the diagnosis of the most common ABNF mistake:
// a bare LF line ending (e.g. from `echo "a = b"`) where CR LF is required. The
// error must report what was found and hint at the line-ending cause.
func Test_U_ParseError_BareLF(t *testing.T) {
	_, err := ParseABNF([]byte("a = b\n"))
	require.Error(t, err)

	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	assert.Contains(t, pe.Found, "LF", "found token names the bare LF")
	assert.NotEmpty(t, pe.Hint, "bare LF must produce a hint")
	assert.Contains(t, err.Error(), "CR LF", "rendered error mentions the CR LF requirement")

	// A correct CR LF line ending parses past the syntax layer; the remaining
	// problem is the undefined dependency, not a parse error.
	_, err = ParseABNF([]byte("a = b\r\n"))
	var dep *ErrDependencyNotFound
	assert.True(t, errors.As(err, &dep), "with CR LF, the real error is the missing rule b")
}

// Test_U_Error_Sentinels pins that the promoted sentinels are matchable with
// errors.Is rather than being opaque strings.
func Test_U_Error_Sentinels(t *testing.T) {
	g, err := ParseABNF([]byte("a = <prose>\r\n"), WithValidation(false))
	require.NoError(t, err)
	_, err = g.TransitionGraph("a")
	assert.True(t, errors.Is(err, ErrProseValInTransitionGraph))
}

// Test_U_Error_Join pins that an alternation that is wholly ungeneratable
// aggregates its per-alternative errors with errors.Join, keeping each
// underlying error inspectable with errors.As.
func Test_U_Error_Join(t *testing.T) {
	g, err := ParseABNF([]byte("a = a\r\n"), WithValidation(false))
	require.NoError(t, err)
	_, err = g.Generate(1, "a")
	require.Error(t, err)
	var cyc *ErrCyclicRule
	assert.True(t, errors.As(err, &cyc), "underlying ErrCyclicRule must remain inspectable")
}
