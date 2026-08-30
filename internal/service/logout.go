package service

import (
	"context"

	"github.com/valkey-io/valkey-go/om"

	"neupaneanish.com.np/authentication/internal/errs"
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

	data, dataErr := redis.HGet[utils.LoginAccessSession](
		ctx,
		utils.LoginAccessSessionPrefix,
		userSession.Jti,
		s.cfg.Client,
	)
	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			if err := redis.SRem(
				ctx,
				utils.UserSessionPrefix+userSession.UserID.String(),
				userSession.Jti,
				s.cfg.Client,
			); err != nil {
				s.cfg.Logger.ErrorContext(ctx, "Valkey SRem", "service", serviceName, "error", err)
			}
			return &gatewayAuthenticationv1.LogoutResponse{}, nil
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey Get", "service", serviceName, "error", dataErr)
		return nil, errs.ErrInternalServer
	}

	if err := redis.HDelete[utils.LoginAccessSession](
		ctx,
		utils.LoginAccessSessionPrefix,
		userSession.Jti,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Access Delete", "service", serviceName, "error", err)
	}

	if err := redis.HDelete[utils.LoginRefreshSession](
		ctx,
		utils.LoginRefreshSessionPrefix,
		data.Refresh,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Refresh Delete", "service", serviceName, "error", err)
	}

	if err := redis.SRem(
		ctx,
		utils.UserSessionPrefix+userSession.UserID.String(),
		userSession.Jti,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Access SRem Delete", "service", serviceName, "error", err)
	}

	if err := redis.SRem(
		ctx,
		utils.UserSessionPrefix+userSession.UserID.String(),
		data.Refresh,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey Refresh SRem Delete", "service", serviceName, "error", err)
	}

	return &gatewayAuthenticationv1.LogoutResponse{}, nil
}

func (s *GatewayAuthenticationService) LogoutAll(
	ctx context.Context,
	_ *gatewayAuthenticationv1.LogoutAllRequest,
) (*gatewayAuthenticationv1.LogoutAllResponse, error) {
	serviceName := "LogoutAll"

	userSession := utils.UserSessionContext(ctx)

	if err := s.logoutAll(ctx, userSession.UserID.String(), serviceName); err != nil {
		return nil, err
	}

	return &gatewayAuthenticationv1.LogoutAllResponse{}, nil
}
