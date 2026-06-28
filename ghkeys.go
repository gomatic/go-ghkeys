// Package ghkeys fetches a GitHub user's SSH public keys and converts the
// supported ones into [age] recipients. FetchRecipients GETs
// https://github.com/<username>.keys through a caller-supplied [HTTPClient]
// (so the transport is injectable and testable), parses the authorized-keys
// body, and skips — with a logged warning — any key age cannot represent.
// Failures carry a sentinel ([ErrFetchKeys] or [ErrNoValidKeys]) recoverable
// with errors.Is.
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

// FetchRecipients fetches SSH public keys for a GitHub user and returns age recipients.
func FetchRecipients(ctx context.Context, client HTTPClient, username string) ([]age.Recipient, error) {
	body, err := fetchKeys(ctx, client, username)
	if err != nil {
		return nil, err
	}

	recipients := parseRecipients(body)
	if len(recipients) == 0 {
		return nil, ErrNoValidKeys.Wrap(nil, username)
	}

	return recipients, nil
}

// fetchKeys retrieves the raw authorized-keys body for a GitHub user.
func fetchKeys(ctx context.Context, client HTTPClient, username string) ([]byte, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ErrFetchKeys.Wrap(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrFetchKeys.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchKeys.Wrap(nil, "HTTP", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrFetchKeys.Wrap(err)
	}
	return body, nil
}

// parseRecipients parses every supported SSH public key line into an age
// recipient, skipping (and logging) unsupported keys.
func parseRecipients(body []byte) []age.Recipient {
	var recipients []age.Recipient

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		if rcpt, ok := parseLine(scanner.Text()); ok {
			recipients = append(recipients, rcpt)
		}
	}
	return recipients
}

// parseLine parses one authorized-keys line, returning false for blank or
// unsupported entries.
func parseLine(text string) (age.Recipient, bool) {
	line := strings.TrimSpace(text)
	if line == "" {
		return nil, false
	}

	rcpt, err := agessh.ParseRecipient(line)
	if err != nil {
		slog.Warn("Skipping unsupported key", "key", line[:min(40, len(line))], "error", err)
		return nil, false
	}
	return rcpt, true
}
