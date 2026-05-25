package config_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewJWT(t *testing.T) {
	t.Parallel()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		jwt, jwtErr := config.NewJWT(hex.EncodeToString(privateKey.Seed()), "test")
		require.NoError(t, jwtErr)
		assert.NotNil(t, jwt)

		userID := uuid.NewString()
		role := "Test"
		id := uuid.NewString()

		t.Run("Generate Token", func(t *testing.T) {
			t.Parallel()
			token, tokenErr := jwt.GenerateToken(userID, role, id)
			require.NoError(t, tokenErr)
			assert.NotNil(t, token)

			t.Run("Validate Token", func(t *testing.T) {
				t.Parallel()
				claims, claimsErr := jwt.ValidateToken(token.Access)
				require.NoError(t, claimsErr)
				assert.Equal(t, userID, claims.Subject)
				assert.Equal(t, id, claims.ID)
				assert.Equal(t, role, claims.Role)
			})

			t.Run("Invalid Token", func(t *testing.T) {
				t.Parallel()
				claims, claimsErr := jwt.ValidateToken(rand.Text())
				require.Error(t, claimsErr)
				assert.Nil(t, claims)
			})
		})
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()
		jwt, jwtErr := config.NewJWT(rand.Text(), "test")
		require.Error(t, jwtErr)
		assert.Nil(t, jwt)
	})

	t.Run("Invalid Key", func(t *testing.T) {
		t.Parallel()
		jwt, jwtErr := config.NewJWT(hex.EncodeToString(privateKey), "Test")
		require.Error(t, jwtErr)
		assert.Nil(t, jwt)
	})
}
