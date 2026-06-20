package service

import (
	"neupaneanish.com.np/authentication/internal/config"
	authv1 "neupaneanish.com.np/authentication/internal/protobuf/auth/v1"
)

type AuthService struct {
	authv1.UnimplementedAuthServiceServer

	cfg *config.Config
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{
		cfg: cfg,
	}
}
