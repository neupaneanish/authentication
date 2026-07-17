//go:build unit

package config_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/config"
)

func TestNewJWT(t *testing.T) {
	t.Parallel()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		newJWT, jwtErr := config.NewJWT(t.Context(), hex.EncodeToString(privateKey.Seed()), "test", logger)
		require.NoError(t, jwtErr)
		assert.NotNil(t, newJWT)

		userID := uuid.NewString()
		role := "Test"
		id := uuid.NewString()

		t.Run("Generate Token", func(t *testing.T) {
			t.Parallel()
			token, tokenErr := newJWT.GenerateToken(userID, role, id)
			require.NoError(t, tokenErr)
			assert.NotNil(t, token)
		})
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()
		newJwt, jwtErr := config.NewJWT(t.Context(), rand.Text(), "test", logger)
		require.Error(t, jwtErr)
		assert.Nil(t, newJwt)
	})

	t.Run("Invalid Key", func(t *testing.T) {
		t.Parallel()
		newJwt, jwtErr := config.NewJWT(t.Context(), hex.EncodeToString(privateKey), "Test", logger)
		require.Error(t, jwtErr)
		assert.Nil(t, newJwt)
	})
}
