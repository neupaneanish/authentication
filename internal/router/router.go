package router

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"neupaneanish.com.np/authentication/internal/config"
)

type HTTPServer struct {
	mux    *http.ServeMux
	http   *http.Server
	logger *slog.Logger
	jwt    *config.JWT
}

const (
	readTimeout     = 15 * time.Second
	writeTimeout    = 15 * time.Second
	idleTimeout     = 60 * time.Second
	shutdownTimeout = 10 * time.Second
)

func NewRouter(
	ctx context.Context,
	logger *slog.Logger,
	jwt *config.JWT,
	port string,
	serverErr chan error,
) {
	mux := http.NewServeMux()
	address := ":" + port

	server := &HTTPServer{
		logger: logger,
		jwt:    jwt,
		mux:    mux,
		http: &http.Server{
			Addr:              address,
			Handler:           mux,
			ReadTimeout:       readTimeout,
			ReadHeaderTimeout: readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			BaseContext: func(_ net.Listener) context.Context {
				return ctx
			},
		},
	}

	lis, lisErr := net.Listen("tcp", address)
	if lisErr != nil {
		serverErr <- lisErr
		return
	}

	server.register()

	go func() {
		logger.InfoContext(ctx, "http server listening", "port", port)
		if hsErr := server.http.Serve(lis); hsErr != nil &&
			!errors.Is(hsErr, http.ErrServerClosed) {
			serverErr <- hsErr
		}
	}()

	go func() {
		<-ctx.Done()
		logger.InfoContext(ctx, "shutting down http server...")
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		err := server.http.Shutdown(stopCtx)
		if err != nil {
			logger.ErrorContext(ctx, "http server shutdown failed", "error", err)
		}
	}()
}
