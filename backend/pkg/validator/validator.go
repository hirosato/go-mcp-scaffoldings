package validator

// Validator provides validation functions for request data
type Validator interface {
	// Validate validates a struct or field based on validation tags
	Validate(i interface{}) error
}

// New creates a new validator
func New() Validator {
	return &stubValidator{}
}

type stubValidator struct{}

func (v *stubValidator) Validate(i interface{}) error {
	return nil
}