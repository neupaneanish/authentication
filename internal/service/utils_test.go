//go:build unit

package service_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/service"
)

func TestLimiterCheck(t *testing.T) {
	t.Parallel()

	resultErr := errors.New("limiter error")
	logger := slog.New(slog.DiscardHandler)

	err := service.LimiterCheck(t.Context(), nil, resultErr, "test", "test", logger)
	require.Error(t, err)
}

func TestAffectedRowCheck(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)

	t.Run("Tag Error", func(t *testing.T) {
		t.Parallel()
		err := service.AffectedRowCheck(
			t.Context(),
			1,
			errors.New("error"),
			"test",
			"test",
			0,
			logger,
		)
		require.Error(t, err)
	})

	t.Run("Affected", func(t *testing.T) {
		t.Parallel()
		err := service.AffectedRowCheck(t.Context(), 0, nil, "test", "test", 1, logger)
		require.Error(t, err)
	})
}
