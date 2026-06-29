package transport

import (
	"google.golang.org/grpc"
	"neupaneanish.com.np/authentication/internal/config"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/service"
)

func register(
	cfg *config.Config,
	server *grpc.Server,
) {
	externalAuthenticationService := service.NewExternalAuthenticationService(cfg)
	externalAuthenticationv1.RegisterAuthenticationServiceServer(server, externalAuthenticationService)

	gatewayAuthenticationService := service.NewGatewayAuthenticationService(cfg)
	gatewayAuthenticationv1.RegisterAuthenticationServiceServer(server, gatewayAuthenticationService)
}
