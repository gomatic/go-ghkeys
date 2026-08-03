package ghkeys

import (
	"bufio"
	"bytes"
	"log/slog"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// Turning a fetched authorized-keys listing into age recipients. Kept apart
// from the fetch path because this half consumes untrusted BYTES rather than
// speaking HTTP: its contracts are about what an arbitrary payload may do —
// an unsupported key is skipped with a warning, but a listing that cannot be
// read to the end is an error rather than a short result.

// keyLine is a single authorized-keys line awaiting parse into a recipient.
type keyLine string

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
