package transport

import (
	"google.golang.org/grpc"
	"neupaneanish.com.np/authentication/internal/config"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/service"
)

func register(
	cfg *config.Config,
	server *grpc.Server,
) {
	authService := service.NewExternalAuthenticationService(cfg)
	externalAuthenticationv1.RegisterAuthenticationServiceServer(server, authService)
}
