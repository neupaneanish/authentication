//go:build integration

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/config"
)

func TestRedpanda(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		rp, err := config.NewRedpanda(t.Context(), redpandaURL, "Test")
		require.NoError(t, err)
		assert.NotNil(t, rp)
	})

	t.Run("Ping Error", func(t *testing.T) {
		t.Parallel()
		rp, err := config.NewRedpanda(t.Context(), "localhost:1234", "Test")
		require.Error(t, err)
		assert.Nil(t, rp)
	})
}
