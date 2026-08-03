package ghkeys

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaxKeysBytesCapsTheBodyRead names maxKeysBytes' claim. The bound is the
// only thing between this library and a compromised or MITM'd github.com
// returning an endless body: without it io.ReadAll grows until the process is
// killed, and a caller fetching keys for a list of users hands an attacker one
// OOM per request.
func TestMaxKeysBytesCapsTheBodyRead(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	// One valid key up front, then blank lines padding the body well past the
	// cap. With io.LimitReader the read must stop at maxKeysBytes, never the
	// full payload, and the trailing blank lines never trip the token limit.
	data := append([]byte(generateEd25519Key(t)), bytes.Repeat([]byte("\n"), maxKeysBytes)...)
	must.Greater(len(data), maxKeysBytes)

	var readCount int
	client := countingClient{data: data, read: &readCount}

	rcpts, err := FetchRecipients(context.Background(), client, "testuser")
	must.NoError(err)
	want.Len(rcpts, 1)
	// The read halted exactly at the cap, leaving the oversized tail unread.
	want.Equal(maxKeysBytes, readCount)
	want.Less(readCount, len(data))
}

// TestKeysRequestEscapesEveryTargetRewritingCharacter names keysRequest' claim.
// The username is caller-supplied and lands in a request target, so each
// character below rewrites that target if interpolated raw: a slash adds path
// segments (reaching another user's keys, or another endpoint entirely), a
// question mark turns the rest into a query, and a hash truncates the path at a
// fragment. Escaping keeps the whole value one path segment.
//
// The host is asserted every time: whatever the username contains, the request
// must still go to github.com and nowhere else.
func TestKeysRequestEscapesEveryTargetRewritingCharacter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		username Username
		want     string
	}{
		{name: "slash adds a path segment", username: "a/b", want: "https://github.com/a%2Fb.keys"},
		{name: "traversal", username: "../settings", want: "https://github.com/..%2Fsettings.keys"},
		{name: "question mark starts a query", username: "a?b=c", want: "https://github.com/a%3Fb=c.keys"},
		{name: "hash starts a fragment", username: "a#b", want: "https://github.com/a%23b.keys"},
		{name: "an ordinary name is untouched", username: "octocat", want: "https://github.com/octocat.keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want, must := assert.New(t), require.New(t)

			var requested string
			client := capturingClient{url: &requested, body: generateEd25519Key(t)}

			rcpts, err := FetchRecipients(context.Background(), client, tc.username)

			must.NoError(err)
			want.Len(rcpts, 1)
			want.Equal(tc.want, requested)
			want.True(strings.HasPrefix(requested, "https://github.com/"),
				"the request must reach github.com whatever the username contains")
		})
	}
}

// countingBody serves data while recording how many bytes are actually read
// from it, so a test can prove the body read stops at the cap.
type countingBody struct {
	read *int
	data []byte
	pos  int
}

// countingClient returns a response whose body counts the bytes read from it.
type countingClient struct {
	read *int
	data []byte
}

// capturingClient records the request URL and returns a valid key body.
type capturingClient struct {
	url  *string
	body string
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	*b.read += n
	return n, nil
}

func (c countingClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(&countingBody{data: c.data, read: c.read}),
	}, nil
}

func (c capturingClient) Do(req *http.Request) (*http.Response, error) {
	*c.url = req.URL.String()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

// TestErrFetchKeysWrapsANonOKStatus names the second condition ErrFetchKeys
// speaks for, at the boundary the body cap does not cover: a response that is
// not 200 carries no keys, and reading its body as an authorized-keys listing
// would parse an HTML error page into recipients. It must be a matchable
// failure instead.
func TestErrFetchKeysWrapsANonOKStatus(t *testing.T) {
	t.Parallel()

	_, err := fetchKeys(context.Background(), statusClient{code: 404}, "octocat")

	assert.ErrorIs(t, err, ErrFetchKeys)
	assert.NotErrorIs(t, err, ErrNoValidKeys)
}

// statusClient returns a response with a chosen status code and an empty body.
type statusClient struct{ code int }

func (c statusClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.code,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

// FuzzKeysRequest drives the username→URL builder with arbitrary strings — the
// other untrusted-input seam. The security contract under fuzz: no username,
// however hostile, may escape its single path segment. The escaped path is
// always exactly "/<escaped>.keys" — one leading slash, no injected segments —
// so a slash-, dot-dot-, query-, or fragment-bearing login cannot rewrite the
// request target.
func FuzzKeysRequest(f *testing.F) {
	for _, seed := range []string{"octocat", "a/b", "../../etc/passwd", "a b", "日本語", "", "a?b#c=d", "%2e%2e%2f", "\x00"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		escaped := keysRequest(context.Background(), Username(name)).URL.EscapedPath()
		if !strings.HasPrefix(escaped, "/") || strings.Count(escaped, "/") != 1 {
			t.Fatalf("username %q injected a path segment: %q", name, escaped)
		}
		if !strings.HasSuffix(escaped, ".keys") {
			t.Fatalf("username %q broke the .keys suffix: %q", name, escaped)
		}
	})
}
