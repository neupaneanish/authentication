//go:build integration

package config_test

import (
	"crypto/ed25519"
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
	t.Setenv("DATABASE_URL", databaseURL)
	t.Setenv("VALKEY_URL", valkeyURL)

	_, jwtPrivate, jwtKeyErr := ed25519.GenerateKey(nil)
	require.NoError(t, jwtKeyErr)
	t.Setenv("JWT_KEY", hex.EncodeToString(jwtPrivate.Seed()))

	_, tfPrivate, tfKeyErr := ed25519.GenerateKey(nil)
	require.NoError(t, tfKeyErr)
	t.Setenv("TWO_FACTOR_KEY", hex.EncodeToString(tfPrivate.Seed()))

	t.Setenv("TELEMETRY_URL", "127.0.0.1:4317")

	env, envErr := config.LoadEnv()
	require.NoError(t, envErr)
	assert.NotNil(t, env)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, cfgErr := config.NewConfig(t.Context(), env, logger)
	require.NoError(t, cfgErr)
	assert.NotNil(t, cfg)

	cfg.Close()
}
