package transport

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func loggerInterceptor(logger *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, level logging.Level, msg string, fields ...any) {
		logger.Log(ctx, slog.Level(level), msg, fields...)
	})
}

func unaryTimeoutInterceptor(defaultTimeout time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := ctx.Deadline(); ok {
			return handler(ctx, req)
		}

		newCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
		defer cancel()

		resp, err := handler(newCtx, req)

		if err != nil && newCtx.Err() != nil {
			if errors.Is(newCtx.Err(), context.DeadlineExceeded) {
				return nil, status.Error(codes.DeadlineExceeded, "request timeout exceeded")
			}
			if errors.Is(newCtx.Err(), context.Canceled) {
				return nil, status.Error(codes.Canceled, "request canceled by client")
			}
		}
		return resp, err
	}
}

func streamTimeoutInterceptor(maxDuration time.Duration) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, maxDuration)
			defer cancel()

			ss = &wrappedTimeoutStream{
				ServerStream: ss,
				ctx:          ctx,
			}
		}

		err := handler(srv, ss)

		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return status.Error(codes.DeadlineExceeded, "stream timeout exceeded")
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return status.Error(codes.Canceled, "stream canceled by client")
			}
		}
		return err
	}
}

type wrappedTimeoutStream struct {
	grpc.ServerStream

	ctx context.Context
}

func (w *wrappedTimeoutStream) Context() context.Context {
	return w.ctx
}
