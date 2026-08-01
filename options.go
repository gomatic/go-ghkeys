package ghkeys

import "log/slog"

// The option surface. Kept apart from the fetch path because it is the only
// part of this package a caller can extend, and its contract — a sealed
// interface whose apply is a pure value transform — is about what a caller
// CANNOT do.

// Option configures a FetchRecipients call. Options are type-based so the
// compiler verifies each one and the public surface stays additive. The
// interface is sealed (config is package-private, so only this package can
// implement it) and apply is a pure value transform — it receives the current
// config and returns the updated one — so options never mutate shared state
// through a pointer.
type Option interface {
	apply(config) config
}

// Logger is an Option that routes the skip warning (emitted for keys age
// cannot represent) to a specific slog.Logger instead of slog.Default.
type Logger struct{ *slog.Logger }

// apply returns the config with the injected logger set.
func (o Logger) apply(c config) config {
	c.logger = o.Logger
	return c
}

var _ Option = Logger{}

// config holds the resolved collaborators for a single FetchRecipients call.
type config struct {
	logger *slog.Logger
}
