//go:build integration

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewDatabase(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		pool, poolErr := config.NewDatabase(t.Context(), databaseURL)
		require.NoError(t, poolErr)
		assert.NotNil(t, pool)
	})

	t.Run("Invalid url", func(t *testing.T) {
		pool, poolErr := config.NewDatabase(t.Context(), "invalid-url")
		require.Error(t, poolErr)
		assert.Nil(t, pool)
	})
}
