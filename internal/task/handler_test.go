//go:build unit

package task_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/task"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	env := &task.Env{
		ValkeyURL:   rand.Text(),
		SMTP2GO:     rand.Text(),
		SenderEmail: "no-reply@neupaneanish.com.np",
	}

	emailHandler := task.NewEmailHandler(env)
	assert.NotNil(t, emailHandler)

	t.Run("Auth Email Empty Payload", func(t *testing.T) {
		t.Parallel()
		emailTask, emailTaskErr := task.AuthEmailTask(task.TypeEmailVerification, "", "")
		require.NoError(t, emailTaskErr)
		assert.NotNil(t, emailTask)

		err := emailHandler.HandleAuthEmailTask(t.Context(), emailTask)
		require.Error(t, err)
	})

	t.Run("Auth Email Success", func(t *testing.T) {
		t.Parallel()
		emailTask, emailTaskErr := task.AuthEmailTask(task.TypeEmailVerification, "test@test.com", "12345678")
		require.NoError(t, emailTaskErr)
		assert.NotNil(t, emailTask)

		err := emailHandler.HandleAuthEmailTask(t.Context(), emailTask)
		require.Error(t, err)
	})

	t.Run("Security Email Empty Payload", func(t *testing.T) {
		t.Parallel()
		emailTask, emailTaskErr := task.SecurityNotification(task.TypePasswordChanged, "")
		require.NoError(t, emailTaskErr)
		assert.NotNil(t, emailTask)

		err := emailHandler.HandleSecurityEmailTask(t.Context(), emailTask)
		require.Error(t, err)
	})

	t.Run("Security Email Success", func(t *testing.T) {
		t.Parallel()
		emailTask, emailTaskErr := task.SecurityNotification(task.TypePasswordChanged, "test@test.com")
		require.NoError(t, emailTaskErr)
		assert.NotNil(t, emailTask)

		err := emailHandler.HandleSecurityEmailTask(t.Context(), emailTask)
		require.Error(t, err)
	})
}
