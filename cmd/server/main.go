package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"neupaneanish.com.np/api/internal/config"
	"neupaneanish.com.np/api/internal/telemetry"
	"neupaneanish.com.np/api/internal/transport"
)

const (
	shutdownTimeout = 10 * time.Second
)

func main() {
	baseLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, ctxStop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer ctxStop()

	baseLogger.InfoContext(ctx, "Environment loading")
	env, envErr := config.LoadEnv(ctx)
	if envErr != nil {
		baseLogger.ErrorContext(ctx, "Environment loading failed", "error", envErr)
		return
	}
	baseLogger.InfoContext(ctx, "Environment loaded successfully")

	logger, shutdown, loggerErr := telemetry.NewTelemetry(ctx, env.TelemetryURL, env.ServiceName, env.Environment)
	if loggerErr != nil {
		baseLogger.ErrorContext(ctx, "Telemetry Setup Failed", "error", loggerErr)
		return
	}
	baseLogger.InfoContext(ctx, "Telemetry loaded successfully")

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			shutdownTimeout,
		)
		defer cancel()
		if loggerErr = shutdown(shutdownCtx); loggerErr != nil {
			baseLogger.ErrorContext(shutdownCtx, "Telemetry shutdown failed", "error", loggerErr)
		}
	}()

	logger.InfoContext(ctx, "Config loading")
	cfg, cfgErr := config.NewConfig(ctx, env, logger)
	if cfgErr != nil {
		logger.ErrorContext(ctx, "Failed to setup config", "error", cfgErr)
		return
	}
	logger.InfoContext(ctx, "Config loaded successfully")
	defer cfg.Close()

	serverErr := make(chan error, 1)

	transportErr := transport.NewTransport(ctx, cfg, serverErr)
	if transportErr != nil {
		logger.ErrorContext(ctx, "Failed to initialize transport", "error", transportErr)
		return
	}

	select {
	case err := <-serverErr:
		logger.ErrorContext(ctx, "gRPC server failed", "error", err)
	case <-ctx.Done():
		logger.InfoContext(ctx, "Shutting down signal received")
	}
}
