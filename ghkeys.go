// Package ghkeys fetches a GitHub user's SSH public keys and converts the
// supported ones into [age] recipients. FetchRecipients GETs
// https://github.com/<username>.keys through a caller-supplied [HTTPClient]
// (so the transport is injectable and testable), parses the authorized-keys
// body, and skips — with a warning logged to an injectable [Logger] — any key
// age cannot represent. Failures carry a sentinel ([ErrFetchKeys] or
// [ErrNoValidKeys]) recoverable with errors.Is.
package ghkeys

import (
	"context"
	"log/slog"
	"net/http"

	"filippo.io/age"
)

// HTTPClient is the interface for making HTTP requests.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Username is the GitHub login whose .keys endpoint is fetched.
type Username string

// keysBody is the raw authorized-keys payload fetched from the GitHub endpoint.
type keysBody []byte

// FetchRecipients fetches SSH public keys for a GitHub user and returns age recipients.
func FetchRecipients(
	ctx context.Context,
	client HTTPClient,
	username Username,
	options ...Option,
) ([]age.Recipient, error) {
	cfg := config{logger: slog.Default()}
	for _, opt := range options {
		cfg = opt.apply(cfg)
	}

	body, err := fetchKeys(ctx, client, username)
	if err != nil {
		return nil, err
	}

	recipients, err := parseRecipients(body, cfg.logger)
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, ErrNoValidKeys.With(nil, username)
	}

	return recipients, nil
}
