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
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

// maxKeysBytes caps how much of an HTTP response body is read, so a compromised
// or MITM'd response cannot exhaust memory. A GitHub .keys listing is a handful
// of short lines; 1 MiB is orders of magnitude beyond any legitimate response.
const maxKeysBytes = 1 << 20

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
func FetchRecipients(
	ctx context.Context,
	client HTTPClient,
	username Username,
	options ...Option,
) ([]age.Recipient, error) {
	cfg := config{logger: slog.Default()}
	for _, opt := range options {
		opt.Apply(&cfg)
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
		return nil, ErrNoValidKeys.wrap(nil, username)
	}

	return recipients, nil
}

// fetchKeys retrieves the raw authorized-keys body for a GitHub user, bounding
// the read at maxKeysBytes so a compromised response cannot exhaust memory.
func fetchKeys(ctx context.Context, client HTTPClient, username Username) (keysBody, error) {
	resp, err := client.Do(keysRequest(ctx, username))
	if err != nil {
		return nil, ErrFetchKeys.wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchKeys.wrap(nil, "HTTP", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBytes))
	if err != nil {
		return nil, ErrFetchKeys.wrap(err)
	}
	return keysBody(body), nil
}

// keysRequest builds the GET request for a user's .keys listing. The username is
// path-escaped into a single path segment via RawPath, so a slash-, query-, or
// fragment-bearing value cannot rewrite the request target. The request is built
// from url.URL fields rather than parsed from a string because, once escaped, the
// target is always well-formed — there is no parse-failure path left to handle.
func keysRequest(ctx context.Context, username Username) *http.Request {
	name := string(username)
	target := &url.URL{
		Scheme:  "https",
		Host:    "github.com",
		Path:    "/" + name + ".keys",
		RawPath: "/" + url.PathEscape(name) + ".keys",
	}
	return (&http.Request{
		Method: http.MethodGet,
		URL:    target,
		Header: make(http.Header),
		Host:   target.Host,
	}).WithContext(ctx)
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
		return nil, ErrFetchKeys.wrap(err)
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
