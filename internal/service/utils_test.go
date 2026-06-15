//go:build unit

package service_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/service"
)

func TestLimiterCheck(t *testing.T) {
	t.Parallel()

	resultErr := errors.New("limiter error")
	logger := slog.New(slog.DiscardHandler)

	err := service.LimiterCheck(t.Context(), nil, resultErr, "test", "test", logger)
	require.Error(t, err)
}

func TestEmailEnqueue(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)

	t.Run("Task Error", func(t *testing.T) {
		t.Parallel()
		tErr := errors.New("task error")
		err := service.EmailEnqueue(t.Context(), nil, tErr, "test", logger, nil)
		require.Error(t, err)
	})

	t.Run("Worker Error", func(t *testing.T) {
		t.Parallel()
		err := service.EmailEnqueue(t.Context(), nil, nil, "test", logger, nil)
		require.Error(t, err)
	})
}
