package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"neupaneanish.com.np/api/internal/config"
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
	_, envErr := config.LoadEnv()
	if envErr != nil {
		baseLogger.ErrorContext(ctx, "Environment loading failed", "error", envErr)
		return
	}
	baseLogger.InfoContext(ctx, "Environment loaded successfully")
}
