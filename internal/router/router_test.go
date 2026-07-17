package router_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/router"
)

func TestNewRouter(t *testing.T) {
	t.Parallel()

	_, privateKey, privateKeyErr := ed25519.GenerateKey(nil)
	require.NoError(t, privateKeyErr)
	logger := slog.New(slog.DiscardHandler)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		jwt, jwtErr := config.NewJWT(t.Context(), hex.EncodeToString(privateKey.Seed()), "Test", logger)
		require.NoError(t, jwtErr)
		serverErr := make(chan error, 1)
		router.NewRouter(t.Context(), logger, jwt, "0", serverErr)
	})

	t.Run("Port Collision", func(t *testing.T) {
		t.Parallel()
		addr := "127.0.0.1:54321"
		lis, err := net.Listen("tcp", addr)
		require.NoError(t, err)

		defer func() {
			lisErr := lis.Close()
			require.NoError(t, lisErr)
		}()

		serverErr := make(chan error, 1)

		jwt := &config.JWT{}

		router.NewRouter(t.Context(), logger, jwt, "54321", serverErr)
	})

	t.Run("Context cancel", func(t *testing.T) {
		t.Parallel()

		serverErr := make(chan error, 1)

		jwt := &config.JWT{}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		router.NewRouter(ctx, logger, jwt, "0", serverErr)
		select {
		case err := <-serverErr:
			require.Error(t, err)
		case <-time.After(50 * time.Millisecond):
		}
	})
}
