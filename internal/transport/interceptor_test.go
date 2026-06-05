//go:build unit

package transport_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"neupaneanish.com.np/api/internal/transport"
)

func TestLoggerInterceptor(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	logger := slog.New(slog.NewJSONHandler(&buf, opts))

	log := transport.LoggerInterceptor(logger)
	log.Log(t.Context(), logging.LevelDebug, "Test", "env", "test")

	output := buf.String()
	assert.Contains(t, output, "Test")
	assert.Contains(t, output, `"level":"DEBUG"`)
	assert.Contains(t, output, `"env":"test"`)
}

func TestUnaryTimeoutInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()
		interceptor := transport.UnaryTimeoutInterceptor(time.Microsecond)
		res, err := interceptor(t.Context(), "test", nil, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("error")
		})

		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("Cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		interceptor := transport.UnaryTimeoutInterceptor(time.Microsecond)
		res, err := interceptor(ctx, "test", nil, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("error")
		})

		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("Deadline", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Microsecond))
		defer cancel()

		interceptor := transport.UnaryTimeoutInterceptor(time.Microsecond)
		res, err := interceptor(ctx, "test", nil, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("error")
		})

		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		interceptor := transport.UnaryTimeoutInterceptor(time.Microsecond)
		res, err := interceptor(t.Context(), "test", nil, func(ctx context.Context, req any) (any, error) {
			return req, nil
		})

		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}

func TestWrappedTimeoutStream_Context(t *testing.T) {
	ctx := t.Context()

	stream := &transport.WrappedTimeoutStream{StreamContext: ctx}

	require.Same(t, ctx, stream.Context())
}

func TestStreamTimeoutInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		stream := &transport.WrappedTimeoutStream{StreamContext: t.Context()}

		interceptor := transport.StreamTimeoutInterceptor(time.Second)

		err := interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv any, stream grpc.ServerStream) error {
			return nil
		})

		require.NoError(t, err)
	})

	t.Run("Deadline", func(t *testing.T) {
		t.Parallel()

		ctxDeadline, cancel := context.WithDeadline(t.Context(), time.Now())
		cancel()

		stream := &transport.WrappedTimeoutStream{StreamContext: ctxDeadline}

		interceptor := transport.StreamTimeoutInterceptor(time.Second)

		err := interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv any, stream grpc.ServerStream) error {
			return stream.Context().Err()
		})

		require.Error(t, err)
	})

	t.Run("Cancel", func(t *testing.T) {
		t.Parallel()
		ctxCancel, cancel := context.WithCancel(t.Context())
		cancel()

		stream := &transport.WrappedTimeoutStream{StreamContext: ctxCancel}
		interceptor := transport.StreamTimeoutInterceptor(time.Minute)

		err := interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv any, stream grpc.ServerStream) error {
			return stream.Context().Err()
		})

		require.Error(t, err)
	})
}
