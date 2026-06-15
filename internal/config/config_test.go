//go:build integration

package config_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/tests"
)

var (
	databaseURL string
	valkeyURL   string
)

func TestMain(m *testing.M) {
	dbURL, dbCleanup, dbErr := tests.Postgres()
	if dbErr != nil {
		panic(dbErr)
	}

	vkURL, valkeyCleanup, valkeyErr := tests.Valkey()
	if valkeyErr != nil {
		dbCleanup()
		panic(valkeyErr)
	}

	databaseURL = dbURL
	valkeyURL = vkURL

	code := m.Run()

	valkeyCleanup()
	dbCleanup()

	os.Exit(code)
}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	_, private, privateKeyErr := ed25519.GenerateKey(nil)
	require.NoError(t, privateKeyErr)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		env := &config.Env{
			DatabaseURL:  databaseURL,
			ValkeyURL:    valkeyURL,
			JWTKey:       hex.EncodeToString(private.Seed()),
			TwoFactorKey: hex.EncodeToString(private.Seed()),
			Issuer:       "Test",
			Port:         "50051",
			ServiceName:  "Test Service",
			Environment:  "production",
			TelemetryURL: "127.0.0.1:4317",
			Domain:       "api.neupaenanish.com.np",
		}

		cfg, cfgErr := config.NewConfig(t.Context(), env, logger)
		require.NoError(t, cfgErr)
		assert.NotNil(t, cfg)

		cfg.Close()
	})

	t.Run("Invalid Pool", func(t *testing.T) {
		t.Parallel()

		env := &config.Env{
			DatabaseURL: "invalid-url",
		}

		cfg, cfgErr := config.NewConfig(t.Context(), env, logger)
		require.Error(t, cfgErr)
		assert.Nil(t, cfg)
	})

	t.Run("Invalid Client", func(t *testing.T) {
		t.Parallel()

		env := &config.Env{
			DatabaseURL: databaseURL,
			ValkeyURL:   "invalid",
		}

		cfg, cfgErr := config.NewConfig(t.Context(), env, logger)
		require.Error(t, cfgErr)
		assert.Nil(t, cfg)
	})

	t.Run("Invalid JWT", func(t *testing.T) {
		t.Parallel()

		env := &config.Env{
			DatabaseURL: databaseURL,
			ValkeyURL:   valkeyURL,
			JWTKey:      rand.Text(),
		}

		cfg, cfgErr := config.NewConfig(t.Context(), env, logger)
		require.Error(t, cfgErr)
		assert.Nil(t, cfg)
	})

	t.Run("Invalid two factor", func(t *testing.T) {
		t.Parallel()

		env := &config.Env{
			DatabaseURL:  databaseURL,
			ValkeyURL:    valkeyURL,
			JWTKey:       hex.EncodeToString(private.Seed()),
			TwoFactorKey: rand.Text(),
		}

		cfg, cfgErr := config.NewConfig(t.Context(), env, logger)
		require.Error(t, cfgErr)
		assert.Nil(t, cfg)
	})
}
