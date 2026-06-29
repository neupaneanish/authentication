package transport

import (
	"context"
	"time"

	"buf.build/go/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"

	protovalidatemiddleware "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"google.golang.org/grpc"
	"neupaneanish.com.np/authentication/internal/config"
)

const (
	interceptorTimeout = 30 * time.Second
	maxTimeout         = 5 * time.Minute
)

func NewOptions(cfg *config.Config) ([]grpc.ServerOption, error) {
	oTelHandler := otelgrpc.NewServerHandler(
		otelgrpc.WithFilter(filters.Not(filters.HealthCheck())),
	)

	validator, validatorErr := protovalidate.New()
	if validatorErr != nil {
		cfg.Logger.Error("proto validate", "error", validatorErr)
		return nil, validatorErr
	}

	recoveryOpt := recovery.WithRecoveryHandler(func(p any) error {
		cfg.Logger.Error("panic recovered in gRPC handler", "panic", p)
		return errs.ErrInternalServer
	})

	externalEndpoints := map[string]struct{}{
		externalAuthenticationv1.AuthenticationService_Register_FullMethodName:                  {},
		externalAuthenticationv1.AuthenticationService_Login_FullMethodName:                     {},
		externalAuthenticationv1.AuthenticationService_LoginTwoFactor_FullMethodName:            {},
		externalAuthenticationv1.AuthenticationService_ForgetPassword_FullMethodName:            {},
		externalAuthenticationv1.AuthenticationService_Verification_FullMethodName:              {},
		externalAuthenticationv1.AuthenticationService_ResetPassword_FullMethodName:             {},
		externalAuthenticationv1.AuthenticationService_AccountVerification_FullMethodName:       {},
		externalAuthenticationv1.AuthenticationService_ResendAccountVerification_FullMethodName: {},
	}

	gatewayEndpoints := map[string]struct{}{
		gatewayAuthenticationv1.AuthenticationService_ChangePassword_FullMethodName:         {},
		gatewayAuthenticationv1.AuthenticationService_VerifyChangePassword_FullMethodName:   {},
		gatewayAuthenticationv1.AuthenticationService_ConfirmChangePassword_FullMethodName:  {},
		gatewayAuthenticationv1.AuthenticationService_EnableTwoFactor_FullMethodName:        {},
		gatewayAuthenticationv1.AuthenticationService_VerifyTwoFactor_FullMethodName:        {},
		gatewayAuthenticationv1.AuthenticationService_ConfirmTwoFactor_FullMethodName:       {},
		gatewayAuthenticationv1.AuthenticationService_DeleteTwoFactor_FullMethodName:        {},
		gatewayAuthenticationv1.AuthenticationService_ConfirmDeleteTwoFactor_FullMethodName: {},
	}

	authFunc := func(ctx context.Context) (context.Context, error) {
		return AuthInterceptor(ctx, externalEndpoints, gatewayEndpoints)
	}

	opts := []grpc.ServerOption{
		grpc.StatsHandler(oTelHandler),
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpt),
			UnaryTimeoutInterceptor(interceptorTimeout),
			protovalidatemiddleware.UnaryServerInterceptor(validator),
			logging.UnaryServerInterceptor(
				LoggerInterceptor(cfg.Logger),
				logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
			),
			auth.UnaryServerInterceptor(authFunc),
		),
		grpc.ChainStreamInterceptor(
			recovery.StreamServerInterceptor(recoveryOpt),
			StreamTimeoutInterceptor(maxTimeout),
			protovalidatemiddleware.StreamServerInterceptor(validator),
			logging.StreamServerInterceptor(
				LoggerInterceptor(cfg.Logger),
				logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
			),
			auth.StreamServerInterceptor(authFunc),
		),
	}

	return opts, nil
}
