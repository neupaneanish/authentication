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
