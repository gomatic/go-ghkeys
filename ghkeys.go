// Package ghkeys fetches a GitHub user's SSH public keys and converts the
// supported ones into [age] recipients. FetchRecipients GETs
// https://github.com/<username>.keys through a caller-supplied [HTTPClient]
// (so the transport is injectable and testable), parses the authorized-keys
// body, and skips — with a warning logged to an injectable [Logger] — any key
// age cannot represent. Failures carry a sentinel ([ErrFetchKeys] or
// [ErrNoValidKeys]) recoverable with errors.Is.
package ghkeys

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// HTTPClient is the interface for making HTTP requests.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Username is the GitHub login whose .keys endpoint is fetched.
type Username string

// keysBody is the raw authorized-keys payload fetched from the GitHub endpoint.
type keysBody []byte

// keyLine is a single authorized-keys line awaiting parse into a recipient.
type keyLine string

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

// parseRecipients parses every supported SSH public key line into an age
// recipient, skipping (and logging via logger) unsupported keys. A scanner
// failure (e.g. a line exceeding the 64 KiB token limit) is surfaced as
// ErrFetchKeys rather than silently truncating the listing.
func parseRecipients(body keysBody, logger *slog.Logger) ([]age.Recipient, error) {
	var recipients []age.Recipient

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		if rcpt, ok := parseLine(keyLine(scanner.Text()), logger); ok {
			recipients = append(recipients, rcpt)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, ErrFetchKeys.With(err)
	}
	return recipients, nil
}

// parseLine parses one authorized-keys line, returning false for blank or
// unsupported entries and warning through logger for the latter.
func parseLine(text keyLine, logger *slog.Logger) (age.Recipient, bool) {
	line := strings.TrimSpace(string(text))
	if line == "" {
		return nil, false
	}

	rcpt, err := agessh.ParseRecipient(line)
	if err != nil {
		logger.Warn("Skipping unsupported key", "key", line[:min(40, len(line))], "error", err)
		return nil, false
	}
	return rcpt, true
}
