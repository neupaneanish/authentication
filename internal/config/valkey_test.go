//go:build integration

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewValkey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		client, clientErr := config.NewValkey(t.Context(), valkeyURL)
		require.NoError(t, clientErr)
		assert.NotNil(t, client)
	})

	t.Run("Invalid URL", func(t *testing.T) {
		client, clientErr := config.NewValkey(t.Context(), "invalid-url")
		require.Error(t, clientErr)
		assert.Nil(t, client)
	})
}
