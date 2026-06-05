package transport

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"
	"neupaneanish.com.np/api/internal/errs"
)

func LoggerInterceptor(logger *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, level logging.Level, msg string, fields ...any) {
		logger.Log(ctx, slog.Level(level), msg, fields...)
	})
}

func UnaryTimeoutInterceptor(defaultTimeout time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := ctx.Deadline(); ok {
			return handler(ctx, req)
		}

		newCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
		defer cancel()

		resp, err := handler(newCtx, req)

		if err != nil && newCtx.Err() != nil {
			if errors.Is(newCtx.Err(), context.DeadlineExceeded) {
				return nil, errs.ErrRequestTimeout
			}
			if errors.Is(newCtx.Err(), context.Canceled) {
				return nil, errs.ErrCanceled
			}
		}
		return resp, err
	}
}

func StreamTimeoutInterceptor(maxDuration time.Duration) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, maxDuration)
			defer cancel()

			ss = &WrappedTimeoutStream{
				ServerStream:  ss,
				StreamContext: ctx,
			}
		}

		err := handler(srv, ss)

		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errs.ErrRequestTimeout
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return errs.ErrCanceled
			}
		}
		return err
	}
}

type WrappedTimeoutStream struct {
	grpc.ServerStream

	StreamContext context.Context
}

func (w *WrappedTimeoutStream) Context() context.Context {
	return w.StreamContext
}
