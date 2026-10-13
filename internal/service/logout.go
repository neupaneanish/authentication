package service

import (
	"context"

	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) Logout(
	ctx context.Context,
	_ *gatewayAuthenticationv1.LogoutRequest,
) (*gatewayAuthenticationv1.LogoutResponse, error) {
	serviceName := "Logout"

	userSession := utils.UserSessionContext(ctx)
	if err := redis.HDelete[utils.Session](
		ctx,
		utils.SessionPrefix,
		userSession.Session,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Access Delete", "service", serviceName, "error", err)
	}

	if err := redis.SRem(
		ctx,
		utils.UserSessionPrefix+userSession.UserID.String(),
		userSession.Session,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey session SRem Delete", "service", serviceName, "error", err)
	}

	return &gatewayAuthenticationv1.LogoutResponse{}, nil
}

func (s *GatewayAuthenticationService) LogoutAll(
	ctx context.Context,
	_ *gatewayAuthenticationv1.LogoutAllRequest,
) (*gatewayAuthenticationv1.LogoutAllResponse, error) {
	serviceName := "LogoutAll"

	userSession := utils.UserSessionContext(ctx)

	LogoutAll(ctx, userSession.UserID.String(), serviceName, s.cfg.Client, s.cfg.Logger)

	return &gatewayAuthenticationv1.LogoutAllResponse{}, nil
}
