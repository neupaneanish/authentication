package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go/om"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *ExternalAuthenticationService) ResetPassword(
	ctx context.Context,
	req *externalAuthenticationv1.ResetPasswordRequest,
) (*externalAuthenticationv1.ResetPasswordResponse, error) {
	serviceName := "ResetPassword"

	result, resultErr := s.cfg.RateLimiter.ResetPassword.Allow(ctx, req.GetSession())
	if limiterErr := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		req.GetSession(),
		s.cfg.Logger,
	); limiterErr != nil {
		return nil, limiterErr
	}

	resetSession, resetSessionErr := redis.HGet[utils.ResetPasswordSession](
		ctx,
		utils.ResetPasswordSessionPrefix,
		req.GetSession(),
		s.cfg.Client,
	)
	if resetSessionErr != nil {
		if om.IsRecordNotFound(resetSessionErr) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" session expired", "session", req.GetSession())
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey hGet", "error", resetSessionErr)
		return nil, errs.ErrInternalServer
	}

	resultUserID, resultUserIDErr := s.cfg.RateLimiter.ResetPasswordUserID.Allow(ctx, resetSession.UserID)
	if userIDLimiterErr := LimiterCheck(
		ctx,
		&resultUserID,
		resultUserIDErr,
		serviceName,
		resetSession.UserID,
		s.cfg.Logger,
	); userIDLimiterErr != nil {
		return nil, userIDLimiterErr
	}

	userID := uuid.MustParse(resetSession.UserID)
	if changeResetPasswordErr := ChangeResetPassword(
		ctx,
		s.cfg.Pool,
		s.cfg.Repository,
		userID,
		serviceName,
		s.cfg.Logger,
		req.GetPassword().GetValue(),
		resetSession.Email,
		true,
		s.cfg.Worker,
	); changeResetPasswordErr != nil {
		return nil, changeResetPasswordErr
	}
	hDeleteErr := redis.HDelete[utils.ResetPasswordSession](
		ctx,
		utils.ResetPasswordSessionPrefix,
		req.GetSession(),
		s.cfg.Client,
	)
	if hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey delete", "error", hDeleteErr)
	}

	return &externalAuthenticationv1.ResetPasswordResponse{}, nil
}
