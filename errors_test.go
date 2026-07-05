package ghkeys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSentinels pins the package's error contract: each sentinel renders its
// declared text and matches only itself under errors.Is. The wrapping mechanism
// (errs.Const.With) is owned and tested by github.com/gomatic/go-error.
func TestSentinels(t *testing.T) {
	t.Parallel()
	want := assert.New(t)

	want.Equal("failed to fetch keys", ErrFetchKeys.Error())
	want.Equal("no valid keys found", ErrNoValidKeys.Error())

	want.ErrorIs(ErrFetchKeys, ErrFetchKeys)
	want.NotErrorIs(ErrFetchKeys, ErrNoValidKeys)
	want.NotErrorIs(ErrNoValidKeys, ErrFetchKeys)
}
