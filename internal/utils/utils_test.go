package utils_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/utils"
)

func TestGetUserSessionContext(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)

	data, err := utils.GetUserSessionContext(t.Context(), "test", logger)
	require.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, errs.ErrPermissionDenied, err)
}
