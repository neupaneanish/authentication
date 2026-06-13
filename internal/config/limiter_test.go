//go:build integration

package config_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/tests"
)

func TestNewLimiter(t *testing.T) {
	t.Parallel()
	client, clientErr := config.NewValkey(t.Context(), valkeyURL)
	require.NoError(t, clientErr)
	assert.NotNil(t, client)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		limiter, limiterErr := config.NewRateLimiter(client)
		require.NoError(t, limiterErr)
		assert.NotNil(t, limiter)

		t.Run("Check", func(t *testing.T) {
			t.Parallel()
			for i := range 6 {
				result, resultErr := limiter.Login.Allow(t.Context(), "test@test.com")
				require.NoError(t, resultErr)
				if i < 5 {
					assert.True(t, result.Allowed)
				} else {
					assert.False(t, result.Allowed)
				}
			}
		})
	})
}

func TestLimiter(t *testing.T) {
	t.Parallel()

	url, cleanup, err := tests.Valkey()
	require.NoError(t, err)

	client, clientErr := config.NewValkey(t.Context(), url)
	require.NoError(t, clientErr)

	prefix := "test"

	identifier := rand.Text()

	t.Run("Success", func(t *testing.T) {
		limiter, limiterErr := config.Limiter(prefix, 1, time.Minute, client)
		require.NoError(t, limiterErr)
		for i := range 2 {
			result, resultErr := limiter.Allow(t.Context(), identifier)
			require.NoError(t, resultErr)

			if i < 1 {
				assert.True(t, result.Allowed)
			} else {
				assert.False(t, result.Allowed)
			}
		}
	})

	t.Run("Failed", func(t *testing.T) {
		t.Parallel()

		t.Run("Invalid limit", func(t *testing.T) {
			limiter, limiterErr := config.Limiter(prefix, 0, time.Minute, client)
			require.Error(t, limiterErr)
			assert.Nil(t, limiter)
		})

		t.Run("Invalid window", func(t *testing.T) {
			limiter, limiterErr := config.Limiter(prefix, 1, 0, client)
			require.Error(t, limiterErr)
			assert.Nil(t, limiter)
		})
	})

	t.Cleanup(cleanup)
}
