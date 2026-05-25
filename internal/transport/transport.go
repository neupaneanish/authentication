package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"neupaneanish.com.np/api/internal/config"
)

const (
	keepAlive        = 15 * time.Second
	maxConnectionAge = 5 * time.Minute
	timeout          = 20 * time.Second
	minTime          = 5 * time.Second
)

func NewTransport(
	ctx context.Context,
	cfg *config.Config,
	serverErr chan error,
) error {
	address := ":" + cfg.Port
	lc := net.ListenConfig{KeepAlive: keepAlive}

	lis, lisErr := lc.Listen(ctx, "tcp", address)
	if lisErr != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, lisErr)
	}

	opts, optsErr := NewOptions(cfg)
	if optsErr != nil {
		return optsErr
	}

	keepaliveParams := grpc.KeepaliveParams(
		keepalive.ServerParameters{
			MaxConnectionAge: maxConnectionAge,
			Time:             time.Minute,
			Timeout:          timeout,
		})

	keepalivePolicy := grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             minTime,
		PermitWithoutStream: true,
	})

	opts = append(opts, keepaliveParams, keepalivePolicy)

	server := grpc.NewServer(opts...)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(server, healthServer)

	go func() {
		cfg.Logger.InfoContext(ctx, "gRPC server listening", "port", cfg.Port)
		healthServer.SetServingStatus(cfg.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)

		if err := server.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			cfg.Logger.ErrorContext(ctx, "gRPC server failed", "error", err)
			serverErr <- err
		}
	}()

	go func() {
		<-ctx.Done()
		cfg.Logger.InfoContext(ctx, "Shutting down gRPC server")

		healthServer.SetServingStatus(cfg.ServiceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)

		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keepAlive)
		defer cancel()

		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			cfg.Logger.InfoContext(ctx, "gRPC server stopped gracefully")
		case <-stopCtx.Done():
			cfg.Logger.WarnContext(ctx, "gRPC shutdown timeout, forcing stop")
			server.Stop()
		}
	}()

	return nil
}
