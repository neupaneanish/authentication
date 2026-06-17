//go:build unit

package config_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewJWT(t *testing.T) {
	t.Parallel()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		newJWT, jwtErr := config.NewJWT(hex.EncodeToString(privateKey.Seed()), "test", logger)
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

			t.Run("Validate Token", func(t *testing.T) {
				t.Parallel()
				claims, claimsErr := newJWT.ValidateToken(token.Access)
				require.NoError(t, claimsErr)
				assert.Equal(t, userID, claims.Subject)
				assert.Equal(t, id, claims.ID)
				assert.Equal(t, role, claims.Role)
			})

			t.Run("Invalid Token", func(t *testing.T) {
				t.Parallel()
				claims, claimsErr := newJWT.ValidateToken(rand.Text())
				require.Error(t, claimsErr)
				assert.Nil(t, claims)
			})
		})
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()
		newJwt, jwtErr := config.NewJWT(rand.Text(), "test", logger)
		require.Error(t, jwtErr)
		assert.Nil(t, newJwt)
	})

	t.Run("Invalid Key", func(t *testing.T) {
		t.Parallel()
		newJwt, jwtErr := config.NewJWT(hex.EncodeToString(privateKey), "Test", logger)
		require.Error(t, jwtErr)
		assert.Nil(t, newJwt)
	})

	t.Run("Invalid Signing method", func(t *testing.T) {
		t.Parallel()

		newJWT, jwtErr := config.NewJWT(hex.EncodeToString(privateKey.Seed()), "test", logger)
		require.NoError(t, jwtErr)
		newToken := jwt.New(jwt.SigningMethodES256)

		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), nil)
		require.NoError(t, keyErr)
		access, signErr := newToken.SignedString(key)
		require.NoError(t, signErr)
		claims, claimsErr := newJWT.ValidateToken(access)
		require.Error(t, claimsErr)
		assert.Nil(t, claims)
	})
}
