package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/config"
)

func TestEmailVerifier(t *testing.T) {
	t.Parallel()

	verifier := config.NewEmailVerifier(false, false)

	t.Run("Invalid Email", func(t *testing.T) {
		t.Parallel()

		err := verifier.Validate("info@anishneupane.com.np")
		require.Error(t, err)
	})

	t.Run("Disposable Email", func(t *testing.T) {
		t.Parallel()

		err := verifier.Validate("lijec51752@dreameg.com")
		require.Error(t, err)
	})

	t.Run("Invalid syntax", func(t *testing.T) {
		t.Parallel()

		err := verifier.Validate("neupaneanish!@$3@gmail.com")
		require.Error(t, err)
	})

	t.Run("Free Email", func(t *testing.T) {
		t.Parallel()

		err := verifier.Validate("neupaneanish@gmail.com")
		require.Error(t, err)
	})

	t.Run("Role Email", func(t *testing.T) {
		t.Parallel()

		err := verifier.Validate("admin@neupaneanish.com.np")
		require.Error(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		err := verifier.Validate("anish@neupaneanish.com.np")
		require.NoError(t, err)
	})
}
