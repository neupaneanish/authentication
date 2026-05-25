//go:build integration

package telemetry_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/telemetry"
	"neupaneanish.com.np/api/tests"
)

func TestNewTelemetry(t *testing.T) {
	url, cleanup, err := tests.OpenTelemetry()
	require.NoError(t, err)
	t.Cleanup(cleanup)

	t.Run("Success", func(t *testing.T) {
		logger, shutdown, tErr := telemetry.NewTelemetry(context.Background(), url, "Test Service", "development")
		require.NoError(t, tErr)
		assert.NotNil(t, logger)

		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, shutdown(ctx))
			require.NoError(t, err)
		})
		logger.InfoContext(t.Context(), "Success")
	})

	t.Run("Invalid URL", func(t *testing.T) {
		logger, shutdown, tErr := telemetry.NewTelemetry(
			context.Background(),
			" %%% :invalid:url",
			"Test Service",
			"development",
		)
		require.Error(t, tErr)
		assert.Nil(t, logger)

		if shutdown != nil {
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = shutdown(ctx)
			})
		}
	})
}
