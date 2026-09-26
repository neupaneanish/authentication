package service

import (
	"context"
	"log/slog"

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
	if err := omNotFound(ctx, dataErr, serviceName, s.cfg.Logger); err != nil {
		return nil, err
	}

	if data.Session != req.GetSession() {
		s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
		s.deleteChangePasswordSession(ctx, userSession.UserID.String(), serviceName)
		return nil, errs.ErrSessionExpired
	}

	if changeResetPasswordErr := ChangeResetPassword(
		ctx,
		userSession,
		serviceName,
		req.GetPassword().GetValue(),
		data.Email,
		false,
		s.cfg.Pool,
		s.cfg.Repository,
		s.cfg.Client,
		s.cfg.Redpanda,
		s.cfg.Logger,
	); changeResetPasswordErr != nil {
		return nil, changeResetPasswordErr
	}

	s.deleteChangePasswordSession(ctx, userSession.UserID.String(), serviceName)
	LogoutAll(ctx, userSession.UserID.String(), serviceName, s.cfg.Client, s.cfg.Logger)

	return &gatewayAuthenticationv1.ChangePasswordResponse{}, nil
}

func (s *GatewayAuthenticationService) deleteChangePasswordSession(ctx context.Context, key, serviceName string) {
	if hDeleteErr := redis.HDelete[utils.ChangePasswordSession](
		ctx,
		utils.ChangePasswordSessionPrefix,
		key,
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete", "service", serviceName, "error", hDeleteErr)
	}
}

func omNotFound(ctx context.Context, err error, serviceName string, logger *slog.Logger) error {
	if err != nil {
		if om.IsRecordNotFound(err) {
			logger.WarnContext(ctx, "session expired", "service", serviceName)
			return errs.ErrSessionExpired
		}
		logger.ErrorContext(ctx, "Valkey get", "service", serviceName, "error", err)
		return errs.ErrInternalServer
	}
	return nil
}
