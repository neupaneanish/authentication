//go:build unit

package config_test

import (
	"crypto/rand"
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
		_ = os.Unsetenv("DOMAIN")
		_ = os.Unsetenv("DOMAIN_VERIFICATION")
		_ = os.Unsetenv("DOMAIN_NAME")
	}

	txt := "DR2JTINSHENMG45HCADCSKYJZS"

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
		t.Setenv("DOMAIN", "neupaneanish.com.np")
		t.Setenv("DOMAIN_VERIFICATION", txt)
		t.Setenv("DOMAIN_NAME", "test")

		env, envErr := config.LoadEnv(t.Context())
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
		t.Setenv("DOMAIN", "neupaneanish.com.np")
		t.Setenv("DOMAIN_VERIFICATION", txt)
		t.Setenv("DOMAIN_NAME", "test")

		env, envErr := config.LoadEnv(t.Context())
		require.NoError(t, envErr)
		assert.NotNil(t, env)
		assert.Equal(t, "50051", env.Port)

		t.Run("Invalid port", func(t *testing.T) {
			t.Setenv("PORT", "79")
			pEnv, pEnvErr := config.LoadEnv(t.Context())
			require.Error(t, pEnvErr)
			assert.Nil(t, pEnv)
		})

		t.Run("Invalid environment", func(t *testing.T) {
			t.Setenv("ENVIRONMENT", "staging")
			pEnv, pEnvErr := config.LoadEnv(t.Context())
			require.Error(t, pEnvErr)
			assert.Nil(t, pEnv)
		})

		t.Run("Invalid domain", func(t *testing.T) {
			cleanup()
			t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/test")
			t.Setenv("VALKEY_URL", "localhost:6379")
			t.Setenv("TWO_FACTOR_KEY", "two-factor-key")
			t.Setenv("JWT_KEY", "jwt-key")
			t.Setenv("TELEMETRY_URL", "127.0.0.1:4317")
			t.Setenv("DOMAIN", "neupaneanish.com.np")
			t.Setenv("DOMAIN_VERIFICATION", rand.Text())
			t.Setenv("DOMAIN_NAME", "test")

			pEnv, pEnvErr := config.LoadEnv(t.Context())
			require.Error(t, pEnvErr)
			assert.Nil(t, pEnv)
		})
	})

	t.Run("Missing Required Environment", func(t *testing.T) {
		requiredVariables := []string{
			"DATABASE_URL",
			"VALKEY_URL",
			"JWT_KEY",
			"TWO_FACTOR_KEY",
			"TELEMETRY_URL",
			"DOMAIN",
			"DOMAIN_VERIFICATION",
			"DOMAIN_NAME",
		}

		for _, v := range requiredVariables {
			t.Run("Missing "+v, func(t *testing.T) {
				for _, all := range requiredVariables {
					t.Setenv(all, txt)
				}

				_ = os.Unsetenv(v)

				env, err := config.LoadEnv(t.Context())
				require.Error(t, err)
				assert.Nil(t, env)
				assert.Contains(t, err.Error(), v)
			})
		}
	})
}
