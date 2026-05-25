package transport_test

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/transport"
)

func TestNewTransport(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	serviceName := "TestService"

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			Logger:      logger,
			Port:        "0",
			ServiceName: serviceName,
		}
		serverErr := make(chan error, 1)

		transportErr := transport.NewTransport(t.Context(), cfg, serverErr)
		require.NoError(t, transportErr)

		time.Sleep(10 * time.Millisecond)

		select {
		case err := <-serverErr:
			require.NoError(t, err)
		case <-time.After(200 * time.Millisecond):
			t.Log("Server shut down gracefully without reporting errors")
		}
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

		cfg := &config.Config{
			Logger:      logger,
			Port:        "54321",
			ServiceName: serviceName,
		}

		serverErr := make(chan error, 1)

		transportErr := transport.NewTransport(t.Context(), cfg, serverErr)
		require.Error(t, transportErr)
	})
}
