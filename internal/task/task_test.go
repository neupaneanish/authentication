//go:build unit

package task_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/task"
)

func TestEmailTask(t *testing.T) {
	t.Parallel()

	t.Run("Auth Email Task", func(t *testing.T) {
		t.Parallel()

		emailTask, emailTaskErr := task.AuthEmailTask(task.TypeEmailVerification, "test@test.com", "12345678")
		require.NoError(t, emailTaskErr)
		assert.NotNil(t, emailTask)
	})

	t.Run("Security Email Task", func(t *testing.T) {
		t.Parallel()

		emailTask, emailTaskErr := task.SecurityNotification(task.TypePasswordChanged, "test@test.com")
		require.NoError(t, emailTaskErr)
		assert.NotNil(t, emailTask)
	})

	t.Run("Payload Task error", func(t *testing.T) {
		t.Parallel()

		payloadTask, err := task.PayloadTask(nil, "test", errors.New("payload error"))
		require.Error(t, err)
		assert.Nil(t, payloadTask)
	})
}
