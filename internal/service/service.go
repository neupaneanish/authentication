package service

import (
	"neupaneanish.com.np/authentication/internal/config"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
)

type ExternalAuthenticationService struct {
	externalAuthenticationv1.UnimplementedAuthenticationServiceServer

	cfg *config.Config
}

func NewExternalAuthenticationService(cfg *config.Config) *ExternalAuthenticationService {
	return &ExternalAuthenticationService{
		cfg: cfg,
	}
}

type GatewayAuthenticationService struct {
	gatewayAuthenticationv1.UnimplementedAuthenticationServiceServer

	cfg *config.Config
}

func NewGatewayAuthenticationService(cfg *config.Config) *GatewayAuthenticationService {
	return &GatewayAuthenticationService{
		cfg: cfg,
	}
}
