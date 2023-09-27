package goabnf

const (
	defaultDeepnessThreshold = 1024
	defaultValidate          = true
)

// ParseOption defines the interface for Parse functional options.
type ParseOption interface {
	applyParse(*parseOptions)
}

// ParseABNFOption defines the interface for ParseABNF functional options.
type ParseABNFOption interface {
	applyParseABNF(*parseABNFOptions)
}

type parseOptions struct {
	deepnessThreshold int
}

type parseABNFOptions struct {
	validate bool
}

// Defines recursive deepness threshold to stop at.
// Count all unfinished "element" alternatives i.e. rule / group / option.
type deepnessThresholdOption int

var _ ParseOption = (*deepnessThresholdOption)(nil)

func (o deepnessThresholdOption) applyParse(opts *parseOptions) {
	opts.deepnessThreshold = int(o)
}

// WithDeepnessThreshold returns a functional option to define at
// which resursive deepness threshold to stop parsing at.
// Modifying it can lead to panic, use with extreme caution.
// Default is 1024. Setting it to -1 sets no limit to recursion.
func WithDeepnessThreshold(deepnessThreshold int) ParseOption {
	return deepnessThresholdOption(deepnessThreshold)
}

// Defines if proceed to semantic validation.
type validateOption bool

var _ ParseABNFOption = (*validateOption)(nil)

func (o validateOption) applyParseABNF(opts *parseABNFOptions) {
	opts.validate = bool(o)
}

// WithValidation returns a functional option to proceed to
// validation or not.
// Default is true.
func WithValidation(validate bool) ParseABNFOption {
	return validateOption(validate)
}
