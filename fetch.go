package ghkeys

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// Retrieving the raw authorized-keys body from GitHub. Both contracts here are
// about untrusted input: the response body is bounded so a compromised endpoint
// cannot exhaust memory, and the username is escaped so it cannot rewrite the
// request target.

// maxKeysBytes caps how much of an HTTP response body is read, so a compromised
// or MITM'd response cannot exhaust memory. A GitHub .keys listing is a handful
// of short lines; 1 MiB is orders of magnitude beyond any legitimate response.
const maxKeysBytes = 1 << 20

// fetchKeys retrieves the raw authorized-keys body for a GitHub user, bounding
// the read at maxKeysBytes so a compromised response cannot exhaust memory.
func fetchKeys(ctx context.Context, client HTTPClient, username Username) (keysBody, error) {
	resp, err := client.Do(keysRequest(ctx, username))
	if err != nil {
		return nil, ErrFetchKeys.With(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchKeys.With(nil, "HTTP", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBytes))
	if err != nil {
		return nil, ErrFetchKeys.With(err)
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
