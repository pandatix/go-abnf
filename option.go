package goabnf

const (
	defaultValidate = true
)

// ParseABNFOption defines the interface for ParseABNF functional options.
type ParseABNFOption interface {
	applyParseABNF(*parseABNFOptions)
}

type parseABNFOptions struct {
	validate bool
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
