package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
)

func TestLoadEnv(t *testing.T) {
	cleanup := func() {
		_ = os.Unsetenv("DATABASE_URL")
		_ = os.Unsetenv("VALKEY_URL")
		_ = os.Unsetenv("JWT_KEY")
		_ = os.Unsetenv("TWO_FACTOR_KEY")
		_ = os.Unsetenv("PORT")
		_ = os.Unsetenv("ENVIRONMENT")
		_ = os.Unsetenv("TELEMETRY_URL")
		_ = os.Unsetenv("ISSUER")
	}

	t.Run("Success with all variables", func(t *testing.T) {
		cleanup()

		t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/test")
		t.Setenv("VALKEY_URL", "localhost:6379")
		t.Setenv("TWO_FACTOR_KEY", "two-factor-key")
		t.Setenv("JWT_KEY", "jwt-key")
		t.Setenv("PORT", "8080")
		t.Setenv("SERVICE_NAME", "Test Service")
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("TELEMETRY_URL", "127.0.0.1:4317")
		t.Setenv("ISSUER", "Test Issuer")

		env, envErr := config.LoadEnv()
		require.NoError(t, envErr)
		assert.NotNil(t, env)
		assert.Equal(t, "8080", env.Port)
	})

	t.Run("Default Environment", func(t *testing.T) {
		cleanup()
		t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/test")
		t.Setenv("VALKEY_URL", "localhost:6379")
		t.Setenv("TWO_FACTOR_KEY", "two-factor-key")
		t.Setenv("JWT_KEY", "jwt-key")
		t.Setenv("TELEMETRY_URL", "127.0.0.1:4317")

		env, envErr := config.LoadEnv()
		require.NoError(t, envErr)
		assert.NotNil(t, env)
		assert.Equal(t, "50051", env.Port)
	})

	t.Run("Missing Required Environment", func(t *testing.T) {
		requiredVariables := []string{
			"DATABASE_URL",
			"VALKEY_URL",
			"JWT_KEY",
			"TWO_FACTOR_KEY",
			"TELEMETRY_URL",
		}

		for _, v := range requiredVariables {
			t.Run("Missing "+v, func(t *testing.T) {
				for _, all := range requiredVariables {
					t.Setenv(all, "some-value")
				}

				_ = os.Unsetenv(v)

				env, err := config.LoadEnv()
				require.Error(t, err)
				assert.Nil(t, env)
				assert.Contains(t, err.Error(), v)
			})
		}
	})
}
