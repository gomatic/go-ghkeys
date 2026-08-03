package ghkeys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stringBodyClient returns a fixed string body with a 200 status.
type stringBodyClient struct{ body string }

func (c stringBodyClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

// TestErrFetchKeysWrapsAScannerFailure names the fourth condition ErrFetchKeys
// speaks for: a listing that cannot be scanned into lines. Dropping that error
// would return the keys parsed so far as if the listing were complete, so a
// caller would encrypt to a subset of the user's keys without knowing it.
func TestErrFetchKeysWrapsAScannerFailure(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	// A single line longer than bufio's 64 KiB token limit makes scanner.Scan
	// fail; that error must surface as ErrFetchKeys, not be silently dropped.
	client := stringBodyClient{body: strings.Repeat("a", 70*1024)}

	_, err := FetchRecipients(context.Background(), client, "testuser")
	must.ErrorIs(err, ErrFetchKeys)
	must.NotErrorIs(err, ErrNoValidKeys)
}

// FuzzParseRecipients drives the key-body parser with arbitrary bytes — the
// input-consuming seam that turns an untrusted authorized-keys payload into age
// recipients. The contract under fuzz: never panic on any input, and on the one
// error it may emit (a scanner failure) carry ErrFetchKeys with no recipients
// returned alongside.
func FuzzParseRecipients(f *testing.F) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	seeds := [][]byte{
		[]byte(generateEd25519Key(f)),
		[]byte(generateRSAKey(f)),
		[]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=\n"),
		[]byte("ssh-ed25519 not-valid-base64 comment\n"),
		[]byte(""),
		[]byte("\n\n\n"),
		[]byte("   \t  \n"),
		[]byte("日本語 ☃\n\xff\xfe garbage\n"),
		bytes.Repeat([]byte("a"), 100*1024),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		recipients, err := parseRecipients(keysBody(body), logger)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrFetchKeys) {
			t.Fatalf("error did not carry ErrFetchKeys: %v", err)
		}
		if recipients != nil {
			t.Fatalf("recipients returned alongside error: %d", len(recipients))
		}
	})
}
