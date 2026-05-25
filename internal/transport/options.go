package transport

import (
	"time"

	"buf.build/go/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"

	protovalidatemiddleware "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"neupaneanish.com.np/api/internal/config"
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
		return nil, validatorErr
	}

	recoveryOpt := recovery.WithRecoveryHandler(func(p any) error {
		cfg.Logger.Error("panic recovered in gRPC handler", "panic", p)
		return status.Error(codes.Internal, "Internal server error")
	})

	opts := []grpc.ServerOption{
		grpc.StatsHandler(oTelHandler),
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpt),
			logging.UnaryServerInterceptor(
				loggerInterceptor(cfg.Logger),
				logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
			),
			protovalidatemiddleware.UnaryServerInterceptor(validator),
			unaryTimeoutInterceptor(interceptorTimeout),
		),
		grpc.ChainStreamInterceptor(
			recovery.StreamServerInterceptor(recoveryOpt),
			logging.StreamServerInterceptor(
				loggerInterceptor(cfg.Logger),
				logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
			),
			protovalidatemiddleware.StreamServerInterceptor(validator),
			streamTimeoutInterceptor(maxTimeout),
		),
	}

	return opts, nil
}
