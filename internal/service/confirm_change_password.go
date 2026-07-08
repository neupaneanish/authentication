package service

import (
	"context"

	"github.com/valkey-io/valkey-go/om"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ConfirmChangePassword(
	ctx context.Context,
	req *gatewayAuthenticationv1.ConfirmChangePasswordRequest,
) (*gatewayAuthenticationv1.ConfirmChangePasswordResponse, error) {
	serviceName := "ConfirmChangePassword"

	userSession, _, _, err := s.gatewayUserSessionLimiter(ctx, serviceName, enum.ChangePassword)
	if err != nil {
		return nil, err
	}

	data, dataErr := redis.HGet[utils.GatewaySecurityVerificationChangePasswordSession](
		ctx,
		utils.VerifyChangePasswordSessionPrefix,
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

	if hDeleteErr := redis.HDelete[utils.GatewaySecurityVerificationChangePasswordSession](
		ctx,
		utils.VerifyChangePasswordSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	); hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete", "service", serviceName, "error", hDeleteErr)
	}
	// TODO: Delete all sessions
	return &gatewayAuthenticationv1.ConfirmChangePasswordResponse{}, nil
}
