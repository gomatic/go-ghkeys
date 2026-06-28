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
	"context"
	"fmt"
	"io"
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

// Option configures a FetchRecipients call. Options are type-based so the
// compiler verifies each one and the public surface stays additive.
type Option interface {
	Apply(*config)
}

// Logger is an Option that routes the skip warning (emitted for keys age
// cannot represent) to a specific slog.Logger instead of slog.Default.
type Logger struct{ *slog.Logger }

// Apply sets the injected logger on the call config.
func (o Logger) Apply(c *config) { c.logger = o.Logger }

var _ Option = Logger{}

// config holds the resolved collaborators for a single FetchRecipients call.
type config struct {
	logger *slog.Logger
}

// FetchRecipients fetches SSH public keys for a GitHub user and returns age recipients.
func FetchRecipients(ctx context.Context, client HTTPClient, username Username, options ...Option) ([]age.Recipient, error) {
	cfg := config{logger: slog.Default()}
	for _, opt := range options {
		opt.Apply(&cfg)
	}

	body, err := fetchKeys(ctx, client, username)
	if err != nil {
		return nil, err
	}

	recipients := parseRecipients(body, cfg.logger)
	if len(recipients) == 0 {
		return nil, ErrNoValidKeys.wrap(nil, username)
	}

	return recipients, nil
}

// fetchKeys retrieves the raw authorized-keys body for a GitHub user.
func fetchKeys(ctx context.Context, client HTTPClient, username Username) ([]byte, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ErrFetchKeys.wrap(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrFetchKeys.wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchKeys.wrap(nil, "HTTP", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrFetchKeys.wrap(err)
	}
	return body, nil
}

// parseRecipients parses every supported SSH public key line into an age
// recipient, skipping (and logging via logger) unsupported keys.
func parseRecipients(body []byte, logger *slog.Logger) []age.Recipient {
	var recipients []age.Recipient

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		if rcpt, ok := parseLine(scanner.Text(), logger); ok {
			recipients = append(recipients, rcpt)
		}
	}
	return recipients
}

// parseLine parses one authorized-keys line, returning false for blank or
// unsupported entries and warning through logger for the latter.
func parseLine(text string, logger *slog.Logger) (age.Recipient, bool) {
	line := strings.TrimSpace(text)
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
