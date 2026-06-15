//go:build unit

package task_test

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/task"
)

func TestLoadWorkerEnv(t *testing.T) {
	cleanup := func() {
		_ = os.Unsetenv("VALKEY_URL")
		_ = os.Unsetenv("SMTP2GO_API")
		_ = os.Unsetenv("SENDER_URL")
	}

	t.Run("Success", func(t *testing.T) {
		cleanup()

		t.Setenv("VALKEY_URL", "localhost:6379")
		t.Setenv("SMTP2GO_API", rand.Text())
		t.Setenv("SENDER_URL", "neupaneanish.com.np")

		env, envErr := task.LoadWorkerEnv()
		require.NoError(t, envErr)
		assert.NotNil(t, env)
	})

	t.Run("Missing Environment", func(t *testing.T) {
		requiredVariables := []string{
			"VALKEY_URL",
			"SMTP2GO_API",
			"SENDER_URL",
		}

		for _, v := range requiredVariables {
			t.Run("Missing "+v, func(t *testing.T) {
				for _, all := range requiredVariables {
					t.Setenv(all, rand.Text())
				}

				_ = os.Unsetenv(v)

				env, envErr := task.LoadWorkerEnv()
				require.Error(t, envErr)
				assert.Nil(t, env)
				assert.Contains(t, envErr.Error(), v)
			})
		}
	})

	t.Run("Invalid domain", func(t *testing.T) {
		cleanup()

		t.Setenv("VALKEY_URL", "localhost:6379")
		t.Setenv("SMTP2GO_API", rand.Text())
		t.Setenv("SENDER_URL", "neup:ane:anish.com.np")

		env, envErr := task.LoadWorkerEnv()
		require.Error(t, envErr)
		assert.Nil(t, env)
	})
}
