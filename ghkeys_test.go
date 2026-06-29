package ghkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func generateEd25519Key(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func generateRSAKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestFetchRecipients(t *testing.T) {
	t.Parallel()

	ed25519Key := generateEd25519Key(t)
	rsaKey := generateRSAKey(t)

	tests := []struct {
		wantErr   error
		name      string
		body      string
		status    int
		wantCount int
	}{
		{
			name:      "ed25519 key",
			body:      ed25519Key,
			status:    http.StatusOK,
			wantCount: 1,
		},
		{
			name:      "RSA key",
			body:      rsaKey,
			status:    http.StatusOK,
			wantCount: 1,
		},
		{
			name:      "mixed keys",
			body:      ed25519Key + rsaKey,
			status:    http.StatusOK,
			wantCount: 2,
		},
		{
			name:      "mixed with unsupported ECDSA prefix",
			body:      ed25519Key + "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=\n" + rsaKey,
			status:    http.StatusOK,
			wantCount: 2,
		},
		{
			name:    "no keys - empty response",
			body:    "",
			status:  http.StatusOK,
			wantErr: ErrNoValidKeys,
		},
		{
			name:    "HTTP error",
			body:    "not found",
			status:  http.StatusNotFound,
			wantErr: ErrFetchKeys,
		},
		{
			name:    "only blank lines",
			body:    "\n\n\n",
			status:  http.StatusOK,
			wantErr: ErrNoValidKeys,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want, must := assert.New(t), require.New(t)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			// Override the URL by using a custom client that rewrites requests
			client := &rewriteClient{base: srv.Client(), targetURL: srv.URL}

			rcpts, err := FetchRecipients(context.Background(), client, "testuser")

			if tt.wantErr != nil {
				must.Error(err)
				want.ErrorIs(err, tt.wantErr)
				return
			}

			must.NoError(err)
			want.Len(rcpts, tt.wantCount)
		})
	}
}

// captureHandler is a minimal slog.Handler that records the messages it
// receives, so a test can assert the skip warning went through the injected
// logger rather than the global one.
type captureHandler struct{ messages *[]string }

func (captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h captureHandler) Handle(_ context.Context, r slog.Record) error {
	*h.messages = append(*h.messages, r.Message)
	return nil
}

func (h captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h captureHandler) WithGroup(string) slog.Handler { return h }

func TestFetchRecipients_InjectedLogger(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	ed25519Key := generateEd25519Key(t)
	var messages []string
	logger := slog.New(captureHandler{messages: &messages})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=\n" + ed25519Key))
	}))
	defer srv.Close()

	client := &rewriteClient{base: srv.Client(), targetURL: srv.URL}

	rcpts, err := FetchRecipients(context.Background(), client, "testuser", Logger{logger})

	must.NoError(err)
	want.Len(rcpts, 1)
	// The unsupported key warned through the injected logger, not the global.
	want.Equal([]string{"Skipping unsupported key"}, messages)
}

// rewriteClient rewrites the request URL to point at the test server.
type rewriteClient struct {
	base      *http.Client
	targetURL string
}

func (c *rewriteClient) Do(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = c.targetURL[len("http://"):]
	return c.base.Do(req)
}

// errClient always fails Do, exercising the request-failure path.
type errClient struct{}

func (errClient) Do(*http.Request) (*http.Response, error) {
	return nil, errSentinel
}

var errSentinel = errString("network down")

type errString string

func (e errString) Error() string { return string(e) }

func TestFetchRecipients_DoError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, err := FetchRecipients(context.Background(), errClient{}, "testuser")
	must.ErrorIs(err, ErrFetchKeys)
}

// bodyErrClient returns a response whose body errors on Read.
type bodyErrClient struct{}

func (bodyErrClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errReader{}),
	}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errSentinel }

func TestFetchRecipients_ReadError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, err := FetchRecipients(context.Background(), bodyErrClient{}, "testuser")
	must.ErrorIs(err, ErrFetchKeys)
}

// countingBody serves data while recording how many bytes are actually read
// from it, so a test can prove the body read stops at the cap.
type countingBody struct {
	read *int
	data []byte
	pos  int
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

// countingClient returns a response whose body counts the bytes read from it.
type countingClient struct {
	read *int
	data []byte
}

func (c countingClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(&countingBody{data: c.data, read: c.read}),
	}, nil
}

func TestFetchRecipients_BodyCapped(t *testing.T) {
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

// capturingClient records the request URL and returns a valid key body.
type capturingClient struct {
	url  *string
	body string
}

func (c capturingClient) Do(req *http.Request) (*http.Response, error) {
	*c.url = req.URL.String()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

func TestFetchRecipients_UsernameEscaped(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	var requested string
	client := capturingClient{url: &requested, body: generateEd25519Key(t)}

	// A slash-bearing username would inject extra path segments if interpolated
	// raw; path-escaping keeps it a single segment ("a%2Fb").
	rcpts, err := FetchRecipients(context.Background(), client, "a/b")
	must.NoError(err)
	want.Len(rcpts, 1)
	want.Equal("https://github.com/a%2Fb.keys", requested)
}

// stringBodyClient returns a fixed string body with a 200 status.
type stringBodyClient struct{ body string }

func (c stringBodyClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

func TestFetchRecipients_ScannerError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	// A single line longer than bufio's 64 KiB token limit makes scanner.Scan
	// fail; that error must surface as ErrFetchKeys, not be silently dropped.
	client := stringBodyClient{body: strings.Repeat("a", 70*1024)}

	_, err := FetchRecipients(context.Background(), client, "testuser")
	must.ErrorIs(err, ErrFetchKeys)
}
