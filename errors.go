package ghkeys

import "fmt"

// Error is ghkeys's sentinel-error type. Every error the package can emit is
// declared as a const of this type, so each one is matchable with errors.Is
// rather than by string comparison. It follows the same shape as the rest of
// the ecosystem's sentinel-error helpers.
type Error string

// Error returns the constant's text, implementing the error interface.
func (e Error) Error() string { return string(e) }

var _ error = Error("")

// wrap returns an error that always carries the sentinel e in its chain (so
// errors.Is(result, e) holds), optionally annotated with context args and a
// wrapped cause. The sentinel e itself is preserved unchanged in the chain;
// context is added as a separate message layer so identity is never lost.
// It is unexported because every error the package emits is constructed here;
// no external consumer wraps these sentinels.
func (e Error) wrap(err error, args ...any) error {
	switch {
	case len(args) > 0 && err != nil:
		return fmt.Errorf("%w: %s: %w", e, fmt.Sprint(args...), err)
	case len(args) > 0:
		return fmt.Errorf("%w: %s", e, fmt.Sprint(args...))
	case err != nil:
		return fmt.Errorf("%w: %w", e, err)
	default:
		return e
	}
}

const (
	// ErrFetchKeys is the leading sentinel wrapped when the GitHub keys endpoint
	// cannot be requested, returns a non-200 status, or its body cannot be read.
	ErrFetchKeys Error = "failed to fetch keys"
	// ErrNoValidKeys is returned when the response contains no SSH public key
	// that could be parsed into an age recipient.
	ErrNoValidKeys Error = "no valid keys found"
)
