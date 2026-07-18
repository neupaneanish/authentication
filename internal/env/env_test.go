//go:build unit

package env_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/env"
)

func TestEnv(t *testing.T) {
	t.Run("Validate Env", func(t *testing.T) {
		t.Run("Missing", func(t *testing.T) {
			value, err := env.ValidateEnv("DEFAULT")
			require.Error(t, err)
			require.Empty(t, value)
		})

		t.Run("Success", func(t *testing.T) {
			t.Setenv("DEFAULT", "default")
			value, err := env.ValidateEnv("DEFAULT")
			require.NoError(t, err)
			assert.Equal(t, "default", value)
		})
	})

	t.Run("Default Env", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			t.Setenv("DEFAULT", "default")
			value := env.ValidateDefaultEnv("DEFAULT", "default")
			assert.Equal(t, "default", value)
		})

		t.Run("Default value", func(t *testing.T) {
			value := env.ValidateDefaultEnv("DEFAULT", "default")
			assert.Equal(t, "default", value)
		})
	})

	t.Run("ValidateBool", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			t.Setenv("TEST_BOOL_KEY", "F")

			ok := env.ValidateBoolEnv("TEST_BOOL_KEY", true)
			assert.False(t, ok)
		})

		t.Run("Invalid", func(t *testing.T) {
			t.Setenv("TEST_BOOL_KEY", "1234")
			ok := env.ValidateBoolEnv("TEST_BOOL_KEY", true)
			assert.True(t, ok)
		})

		t.Run("Empty", func(t *testing.T) {
			ok := env.ValidateBoolEnv("TEST_BOOL_KEY", true)
			assert.True(t, ok)
		})
	})
}
