//go:build unit

package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/utils"
)

func TestPhoneNumber(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()

		number, err := utils.PhoneNumber("")
		require.Error(t, err)
		assert.Empty(t, number)
	})

	t.Run("Invalid Number", func(t *testing.T) {
		t.Parallel()

		number, err := utils.PhoneNumber("1234567890")
		require.Error(t, err)
		assert.Empty(t, number)
	})

	t.Run("Invalid Number with country code", func(t *testing.T) {
		t.Parallel()

		number, err := utils.PhoneNumber("+11234567890")
		require.Error(t, err)
		assert.Empty(t, number)
	})

	t.Run("Valid Number", func(t *testing.T) {
		t.Parallel()

		number, err := utils.PhoneNumber("+16147675416")
		require.NoError(t, err)
		assert.NotEmpty(t, number)
	})
}
