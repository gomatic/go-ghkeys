package ghkeys

import (
	"bytes"
	"log/slog"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOptionIsAPureValueTransform names Option's claim: "apply is a pure value
// transform — it receives the current config and returns the updated one — so
// options never mutate shared state through a pointer."
//
// It matters because callers reuse Option values. slog.Logger is itself a
// pointer, so an apply that wrote through its receiver, or that handed back a
// config aliasing the caller's, would let one FetchRecipients call change where
// a later, unrelated call sends its warnings. Applying an option must leave
// both the option and the input config untouched.
func TestOptionIsAPureValueTransform(t *testing.T) {
	t.Parallel()
	want := assert.New(t)

	var first, second bytes.Buffer
	optA := Logger{slog.New(slog.NewTextHandler(&first, nil))}
	optB := Logger{slog.New(slog.NewTextHandler(&second, nil))}

	base := config{}
	afterA := optA.apply(base)
	afterB := optB.apply(base)

	want.Nil(base.logger, "the input config must be unchanged by apply")
	want.NotSame(afterA.logger, afterB.logger, "each apply returns its own config")
	want.Same(optA.Logger, afterA.logger, "and the option's own value is carried, not copied over")

	// Re-applying the same option to a config that already carries another must
	// produce the later one, without either option having been altered.
	chained := optB.apply(afterA)
	want.Same(optB.Logger, chained.logger)
	want.Same(optA.Logger, afterA.logger, "applying B must not have reached back into A's result")
}

// TestOptionInterfaceIsSealed names the other half of Option's claim: the
// interface is sealed because apply is unexported, so only this package can
// implement it. A caller cannot inject an arbitrary config transform, which is
// what keeps the option set something the compiler can verify rather than an
// open extension point.
func TestOptionInterfaceIsSealed(t *testing.T) {
	t.Parallel()

	// Logger is the package's own option and satisfies the interface.
	var opt Option = Logger{slog.Default()}
	require.NotNil(t, opt)

	// The seal is structural: every method of Option must be unexported, so a
	// type declared in another package cannot satisfy it however it is written.
	// An exported method appearing here would silently open the interface to
	// arbitrary caller-supplied config transforms.
	iface := reflect.TypeOf((*Option)(nil)).Elem()
	require.Positive(t, iface.NumMethod())
	for i := range iface.NumMethod() {
		method := iface.Method(i)
		assert.NotEmpty(t, method.PkgPath,
			"Option.%s is exported, which unseals the interface", method.Name)
	}
}
