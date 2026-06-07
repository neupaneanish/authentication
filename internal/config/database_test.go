//go:build integration

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewDatabase(t *testing.T) {
	t.Parallel()
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		pool, poolErr := config.NewDatabase(t.Context(), databaseURL)
		require.NoError(t, poolErr)
		assert.NotNil(t, pool)
	})

	t.Run("Invalid url", func(t *testing.T) {
		t.Parallel()
		pool, poolErr := config.NewDatabase(t.Context(), "invalid-url")
		require.Error(t, poolErr)
		assert.Nil(t, pool)
	})

	t.Run("Pool", func(t *testing.T) {
		t.Parallel()

		pool, poolErr := config.NewDatabase(t.Context(), "postgres://postgres:postgres@127.0.0.1:5432/alkcnsjbahjvajcabhj?sslmode=disable")
		require.Error(t, poolErr)
		assert.Nil(t, pool)
	})
}
