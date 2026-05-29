//go:build unit

package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/utils"
)

func TestPassword(t *testing.T) {
	t.Parallel()

	t.Run("Create password", func(t *testing.T) {
		t.Parallel()
		testPassword := "Test@123456"

		hash, hashErr := utils.CreatePassword(testPassword)
		require.NoError(t, hashErr)
		assert.NotNil(t, hash)

		t.Run("Compare valid password", func(t *testing.T) {
			t.Parallel()
			ok := utils.ComparePassword(hash, testPassword)
			assert.True(t, ok)
		})

		t.Run("Compare invalid hash password", func(t *testing.T) {
			t.Parallel()
			ok := utils.ComparePassword([]byte("test@123456"), testPassword)
			assert.False(t, ok)
		})

		t.Run("Compare invalid password", func(t *testing.T) {
			t.Parallel()
			ok := utils.ComparePassword(hash, "test@123456")
			assert.False(t, ok)
		})
	})

	t.Run("Create empty password", func(t *testing.T) {
		t.Parallel()
		hash, hashErr := utils.CreatePassword("")
		require.Error(t, hashErr)
		require.Nil(t, hash)
	})

	t.Run("Compare empty password", func(t *testing.T) {
		t.Parallel()
		ok := utils.ComparePassword([]byte("Test"), "")
		assert.False(t, ok)
	})
}
