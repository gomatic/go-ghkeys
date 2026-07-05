package ghkeys

import errs "github.com/gomatic/go-error"

const (
	// ErrFetchKeys is the leading sentinel wrapped when the GitHub keys endpoint
	// cannot be requested, returns a non-200 status, or its body cannot be read.
	ErrFetchKeys errs.Const = "failed to fetch keys"
	// ErrNoValidKeys is returned when the response contains no SSH public key
	// that could be parsed into an age recipient.
	ErrNoValidKeys errs.Const = "no valid keys found"
)
