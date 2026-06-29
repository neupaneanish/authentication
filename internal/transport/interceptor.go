package transport

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/utils"
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

func AuthInterceptor(ctx context.Context, external, gateway map[string]struct{}) (context.Context, error) {
	fullMethod, ok := grpc.Method(ctx)
	if !ok {
		return ctx, errs.ErrInternalServer
	}
	userID := userDetail(ctx, "x-user-id")
	role := userDetail(ctx, "x-role")
	jti := userDetail(ctx, "x-jti")

	hasUserDetail := userID != "" && role != "" && jti != ""

	_, isExternalEndpoint := external[fullMethod]
	_, isGatewayEndpoint := gateway[fullMethod]

	switch {
	case isGatewayEndpoint:
		if hasUserDetail {
			return setContextValue(ctx, userID, role, jti), nil
		}
		return ctx, errs.ErrSessionExpired

	case isExternalEndpoint:
		if hasUserDetail {
			return ctx, errs.ErrPermissionDenied
		}
		return ctx, nil

	case isRefreshEndpoint(fullMethod):
		if hasUserDetail {
			return setContextValue(ctx, userID, role, jti), nil
		}
		return ctx, nil

	default:
		return ctx, errs.ErrPermissionDenied
	}
}

func userDetail(ctx context.Context, header string) string {
	value := metadata.ValueFromIncomingContext(ctx, header)
	if len(value) == 0 {
		return ""
	}
	return value[0]
}

func isRefreshEndpoint(fullMethod string) bool {
	return fullMethod == externalAuthenticationv1.AuthenticationService_Refresh_FullMethodName
}

func setContextValue(ctx context.Context, userID string, role string, jti string) context.Context {
	ctx = logging.InjectFields(ctx, logging.Fields{
		"user_id", userID,
		"role", role,
		"jti", jti,
	})

	return context.WithValue(ctx, utils.SessionKey, utils.UserSession{
		UserID: userID,
		Role:   role,
		Jti:    jti,
	})
}
