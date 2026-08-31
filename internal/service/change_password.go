package service

import (
	"context"

	"github.com/valkey-io/valkey-go/om"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ChangePassword(
	ctx context.Context,
	req *gatewayAuthenticationv1.ChangePasswordRequest,
) (*gatewayAuthenticationv1.ChangePasswordResponse, error) {
	serviceName := "ChangePassword"

	userSession := utils.UserSessionContext(ctx)

	result, resultErr := s.cfg.RateLimiter.PasswordWorkflow.Allow(ctx, userSession.UserID.String())
	if err := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		userSession.UserID.String(),
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}

	data, dataErr := redis.HGet[utils.ChangePasswordSession](
		ctx,
		utils.ChangePasswordSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	)
	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey get", "service", serviceName, "error", dataErr)
		return nil, errs.ErrInternalServer
	}

	if data.Session != req.GetSession() {
		s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
		return nil, errs.ErrSessionExpired
	}

	if changeResetPasswordErr := ChangeResetPassword(
		ctx,
		s.cfg.Pool,
		s.cfg.Repository,
		userSession.UserID,
		serviceName,
		s.cfg.Logger,
		req.GetPassword().GetValue(),
		data.Email,
		false,
		s.cfg.Worker,
	); changeResetPasswordErr != nil {
		return nil, changeResetPasswordErr
	}

	if hDeleteErr := redis.HDelete[utils.ChangePasswordSession](
		ctx,
		utils.ChangePasswordSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete", "service", serviceName, "error", hDeleteErr)
	}

	_ = LogoutAll(ctx, userSession.UserID.String(), serviceName, s.cfg.Client, s.cfg.Logger)

	return &gatewayAuthenticationv1.ChangePasswordResponse{}, nil
}
