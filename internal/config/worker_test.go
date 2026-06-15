//go:build integration

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestNewWorker(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		client, err := config.NewWorker(valkeyURL)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()

		client, err := config.NewWorker("localhost:1234")
		require.Error(t, err)
		assert.Nil(t, client)
	})
}
