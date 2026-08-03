package ghkeys

import errs "github.com/gomatic/go-error"

const (
	// ErrFetchKeys is the leading sentinel wrapped when the GitHub keys endpoint
	// cannot be requested, returns a non-200 status, its body cannot be read, or
	// the fetched listing cannot be scanned into lines (a line past bufio's
	// token limit) — the last so a truncated listing can never pass for a
	// complete one.
	ErrFetchKeys errs.Const = "failed to fetch keys"
	// ErrNoValidKeys is returned when the response contains no SSH public key
	// that could be parsed into an age recipient.
	ErrNoValidKeys errs.Const = "no valid keys found"
)
