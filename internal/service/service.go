package service

import (
	"neupaneanish.com.np/authentication/internal/config"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
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
