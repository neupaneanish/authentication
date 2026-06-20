//go:build integration

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/config"
)

func TestNewValkey(t *testing.T) {
	t.Parallel()
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		client, clientErr := config.NewValkey(t.Context(), valkeyURL)
		require.NoError(t, clientErr)
		assert.NotNil(t, client)
	})

	t.Run("Invalid URL", func(t *testing.T) {
		t.Parallel()
		client, clientErr := config.NewValkey(t.Context(), "invalid-url")
		require.Error(t, clientErr)
		assert.Nil(t, client)
	})
}
