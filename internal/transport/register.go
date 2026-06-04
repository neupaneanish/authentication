package transport

import (
	"google.golang.org/grpc"
	"neupaneanish.com.np/api/internal/config"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/service"
)

func register(
	cfg *config.Config,
	server *grpc.Server,
) {
	authService := service.NewAuthService(cfg)
	authv1.RegisterAuthServiceServer(server, authService)
}
