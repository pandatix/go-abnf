package goabnf

// ParseABNFOption defines the interface for functional options.
type ParseABNFOption interface {
	apply(*options)
}

type options struct {
	validate bool
}

// Defines if proceed to semantic validation.
type validateOption bool

var _ ParseABNFOption = (*validateOption)(nil)

func (vo validateOption) apply(opts *options) {
	opts.validate = bool(vo)
}

// Returns functional option to proceed to validation or not.
func WithValidation(validate bool) ParseABNFOption {
	return validateOption(validate)
}
