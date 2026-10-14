package transport

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	"neupaneanish.com.np/authentication/internal/utils"
)

type MetadataDetails struct {
	UserID   string
	Session  string
	Role     string
	Username string
}

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

func AuthInterceptor(
	ctx context.Context,
	serviceName string,
	external, gateway, root map[string]struct{},
	logger *slog.Logger,
) (context.Context, error) {
	fullMethod, ok := grpc.Method(ctx)
	if !ok {
		return ctx, errs.ErrInternalServer
	}

	_, isExternalEndpoint := external[fullMethod]
	_, isGatewayEndpoint := gateway[fullMethod]
	_, isRootEndpoint := root[fullMethod]

	userMeta, hasUserDetail := userMetadata(ctx)

	switch {
	case isGatewayEndpoint:
		if hasUserDetail {
			return authContext(ctx, serviceName, "", userMeta, logger)
		}
		logger.WarnContext(
			ctx, "missing required headers",
			"service", serviceName,
			"method", fullMethod,
		)
		return ctx, errs.ErrUnauthenticated

	case isRootEndpoint:
		if hasUserDetail {
			return authContext(ctx, serviceName, enum.UserRoleRoot, userMeta, logger)
		}
		logger.WarnContext(
			ctx,
			"missing required headers for root endpoint",
			"service", serviceName,
			"method", fullMethod,
		)
		return ctx, errs.ErrUnauthenticated

	case isExternalEndpoint:
		if hasUserDetail {
			logger.WarnContext(
				ctx,
				"authenticated user blocked from external endpoint",
				"service", serviceName,
				"userID", userMeta.UserID,
			)
			return ctx, errs.ErrPermissionDenied
		}
		return ctx, nil

	default:
		return ctx, errs.ErrPermissionDenied
	}
}

func metadataDetail(ctx context.Context, header string) string {
	value := metadata.ValueFromIncomingContext(ctx, header)
	if len(value) == 0 {
		return ""
	}
	return value[0]
}

func userMetadata(ctx context.Context) (MetadataDetails, bool) {
	xUserID := metadataDetail(ctx, "x-user-id")
	xRole := metadataDetail(ctx, "x-role")
	xSession := metadataDetail(ctx, "x-session")
	xUsername := metadataDetail(ctx, "x-username")

	if xUserID == "" || xRole == "" || xSession == "" || xUsername == "" {
		return MetadataDetails{}, false
	}

	return MetadataDetails{
		UserID:   xUserID,
		Session:  xSession,
		Role:     xRole,
		Username: xUsername,
	}, true
}

func authContext(
	ctx context.Context,
	serviceName string,
	role enum.UserRole,
	meta MetadataDetails,
	logger *slog.Logger,
) (context.Context, error) {
	userID, userIDErr := utils.ParsedUUID(ctx, meta.UserID, serviceName, logger)
	if userIDErr != nil {
		return ctx, errs.ErrUnauthenticated
	}

	userRole := enum.UserRole(meta.Role)
	if !userRole.Valid() {
		logger.WarnContext(ctx, "Invalid role", "service", serviceName, "role", meta.Role)
		return ctx, errs.ErrUnauthenticated
	}

	if role != "" && userRole != role {
		logger.WarnContext(ctx, "Insufficient permissions for endpoint",
			"service", serviceName,
			"userID", meta.UserID,
			"provided_role", meta.Role,
			"required_role", role,
		)
		return ctx, errs.ErrPermissionDenied
	}

	ctx = logging.InjectFields(ctx, logging.Fields{
		"user_id", meta.UserID,
		"role", meta.Role,
		"session", meta.Session,
		"username", meta.Username,
	})

	return context.WithValue(
		ctx,
		utils.SessionKey,
		&utils.UserSession{
			UserID:   userID,
			Username: meta.Username,
			Session:  meta.Session,
		},
	), nil
}
