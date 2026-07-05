# go-ghkeys

Fetch a GitHub user's SSH public keys and convert the supported ones into [age](https://age-encryption.org) recipients: `FetchRecipients(ctx, HTTPClient, username)`. Extracted from `gomatic/ssh-tgzx`'s `internal/ghkeys`.

- Package `ghkeys`, over `filippo.io/age` + stdlib `net/http` (`golang.org/x/crypto` is a test-only dep). The HTTP transport is an injected `HTTPClient` interface, so the GitHub call is fully covered by stub clients. Failures wrap a sentinel `errs.Const` (`ErrFetchKeys`, `ErrNoValidKeys`, from [gomatic/go-error](https://github.com/gomatic/go-error)) matchable with `errors.Is`.
- Gate: gofumpt, vet, staticcheck, govulncheck, gocognit ≤ 7, 100% coverage. Shared config (`Makefile`, `.golangci.yaml`, `.github/`, …) is owned by `nicerobot/tools.repository` — never edit in-tree; use `Makefile.local`.
