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
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"

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
		externalAuthenticationv1.ExternalAuthenticationService_Register_FullMethodName:       {},
		externalAuthenticationv1.ExternalAuthenticationService_Login_FullMethodName:          {},
		externalAuthenticationv1.ExternalAuthenticationService_ForgetPassword_FullMethodName: {},
		externalAuthenticationv1.ExternalAuthenticationService_Verification_FullMethodName:   {},
		externalAuthenticationv1.ExternalAuthenticationService_ResetPassword_FullMethodName:  {},
		externalAuthenticationv1.ExternalAuthenticationService_Resend_FullMethodName:         {},
	}

	gatewayEndpoints := map[string]struct{}{
		gatewayAuthenticationv1.GatewayAuthenticationService_ChangePassword_FullMethodName:              {},
		gatewayAuthenticationv1.GatewayAuthenticationService_PasswordVerification_FullMethodName:        {},
		gatewayAuthenticationv1.GatewayAuthenticationService_PasswordSessionVerification_FullMethodName: {},
		gatewayAuthenticationv1.GatewayAuthenticationService_ConfirmTwoFactor_FullMethodName:            {},
		gatewayAuthenticationv1.GatewayAuthenticationService_Profile_FullMethodName:                     {},
		gatewayAuthenticationv1.GatewayAuthenticationService_Role_FullMethodName:                        {},
		gatewayAuthenticationv1.GatewayAuthenticationService_Logout_FullMethodName:                      {},
		gatewayAuthenticationv1.GatewayAuthenticationService_LogoutAll_FullMethodName:                   {},
		gatewayAuthenticationv1.GatewayAuthenticationService_Resend_FullMethodName:                      {},
	}

	rootEndpoints := map[string]struct{}{
		rootAuthenticationv1.RootAuthenticationService_UpdateRole_FullMethodName:   {},
		rootAuthenticationv1.RootAuthenticationService_UpdateStatus_FullMethodName: {},
		rootAuthenticationv1.RootAuthenticationService_User_FullMethodName:         {},
		rootAuthenticationv1.RootAuthenticationService_Users_FullMethodName:        {},
	}

	authFunc := func(ctx context.Context) (context.Context, error) {
		return AuthInterceptor(ctx, externalEndpoints, gatewayEndpoints, rootEndpoints)
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
