package ghkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestFetchRecipients_BadURL(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	// A username containing a control character yields an invalid URL, so
	// http.NewRequestWithContext fails before any client.Do.
	_, err := FetchRecipients(context.Background(), errClient{}, "bad\x7fuser")
	must.ErrorIs(err, ErrFetchKeys)
}

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
