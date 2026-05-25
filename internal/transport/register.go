package transport

import (
	"google.golang.org/grpc"
	"neupaneanish.com.np/api/internal/config"
)

func register(
	_ *config.Config,
	_ *grpc.Server,
) {
	// TODO: Register all gRPC services
}
