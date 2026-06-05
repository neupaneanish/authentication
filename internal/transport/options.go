package transport

import (
	"time"

	"buf.build/go/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"
	"neupaneanish.com.np/api/internal/errs"

	protovalidatemiddleware "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"google.golang.org/grpc"
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
		cfg.Logger.Error("proto validate", "error", validatorErr)
		return nil, validatorErr
	}

	recoveryOpt := recovery.WithRecoveryHandler(func(p any) error {
		cfg.Logger.Error("panic recovered in gRPC handler", "panic", p)
		return errs.ErrInternalServer
	})

	opts := []grpc.ServerOption{
		grpc.StatsHandler(oTelHandler),
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpt),
			logging.UnaryServerInterceptor(
				LoggerInterceptor(cfg.Logger),
				logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
			),
			protovalidatemiddleware.UnaryServerInterceptor(validator),
			UnaryTimeoutInterceptor(interceptorTimeout),
		),
		grpc.ChainStreamInterceptor(
			recovery.StreamServerInterceptor(recoveryOpt),
			logging.StreamServerInterceptor(
				LoggerInterceptor(cfg.Logger),
				logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
			),
			protovalidatemiddleware.StreamServerInterceptor(validator),
			StreamTimeoutInterceptor(maxTimeout),
		),
	}

	return opts, nil
}
