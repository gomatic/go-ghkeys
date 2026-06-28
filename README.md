# go-ghkeys

Fetch a GitHub user's SSH public keys and turn the supported ones into [age](https://age-encryption.org) recipients. `FetchRecipients` GETs `https://github.com/<username>.keys` through a caller-supplied `HTTPClient` (so the transport is injectable and fully testable), parses the authorized-keys response, and skips — with a logged warning — any key age cannot represent. Depends only on the standard library plus `filippo.io/age`.

## Install

```sh
go get github.com/gomatic/go-ghkeys
```

## Usage

```go
package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gomatic/go-ghkeys"
)

func main() {
	rcpts, err := ghkeys.FetchRecipients(context.Background(), http.DefaultClient, "octocat")
	if err != nil {
		panic(err)
	}
	fmt.Printf("fetched %d age recipients\n", len(rcpts))
}
```

`HTTPClient` is any type with `Do(*http.Request) (*http.Response, error)` — `*http.Client` satisfies it directly, and tests inject a stub.

## Errors

Every failure wraps a sentinel matchable with `errors.Is`:

- `ghkeys.ErrFetchKeys` — the request could not be built or sent, returned a non-200 status, or its body could not be read.
- `ghkeys.ErrNoValidKeys` — the response contained no key parseable into an age recipient.

## Build & test

The `Makefile`, `.golangci.yaml`, `.editorconfig`, `.gitignore`, and `.github/` are the canonical gomatic Go toolchain, owned and distributed by [`nicerobot/tools.repository`](https://github.com/nicerobot/tools.repository) — do not edit them in-tree; per-repo changes belong in a `Makefile.local`. Run the full gate (lint, staticcheck, govulncheck, 100% coverage) with `make check`.
