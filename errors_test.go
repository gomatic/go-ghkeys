package ghkeys

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestError_Error(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "no valid keys found", ErrNoValidKeys.Error())
}

func TestError_Wrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("root cause")

	tests := []struct {
		err         error
		name        string
		wantMessage string
		args        []any
		wantCause   bool
	}{
		{
			name:        "no args no cause returns the bare sentinel",
			wantMessage: "failed to fetch keys",
		},
		{
			name:        "args only",
			args:        []any{"octocat"},
			wantMessage: "failed to fetch keys: octocat",
		},
		{
			name:        "cause only",
			err:         cause,
			wantMessage: "failed to fetch keys: root cause",
			wantCause:   true,
		},
		{
			name:        "args and cause",
			args:        []any{"octocat"},
			err:         cause,
			wantMessage: "failed to fetch keys: octocat: root cause",
			wantCause:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want, must := assert.New(t), require.New(t)

			got := ErrFetchKeys.wrap(tt.err, tt.args...)
			must.Error(got)

			want.Equal(tt.wantMessage, got.Error())
			// The sentinel is always recoverable from the chain.
			want.ErrorIs(got, ErrFetchKeys)
			// A different sentinel must not match.
			want.NotErrorIs(got, ErrNoValidKeys)

			if tt.wantCause {
				want.ErrorIs(got, cause)
			}
		})
	}
}
