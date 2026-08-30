package service

import (
	"context"
	"uuid"

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
	session := req.GetSession()
	result, resultErr := s.cfg.RateLimiter.ResetPassword.Allow(ctx, session)
	if limiterErr := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		session,
		s.cfg.Logger,
	); limiterErr != nil {
		return nil, limiterErr
	}

	resetSession, resetSessionErr := redis.HGet[utils.ResetPasswordSession](
		ctx,
		utils.ResetPasswordSessionPrefix,
		session,
		s.cfg.Client,
	)
	if resetSessionErr != nil {
		if om.IsRecordNotFound(resetSessionErr) {
			s.cfg.Logger.WarnContext(ctx, "Session not found", "service", serviceName, "session", session)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey Get", "service", serviceName, "error", resetSessionErr)
		return nil, errs.ErrInternalServer
	}

	userID, userIDErr := uuid.Parse(resetSession.UserID)
	if userIDErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Invalid UserID", "session", session, "error", userIDErr)
		s.deleteResetPasswordSession(ctx, session, serviceName)
		return nil, errs.ErrSessionExpired
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
	s.deleteResetPasswordSession(ctx, resetSession.Key, serviceName)
	return &externalAuthenticationv1.ResetPasswordResponse{}, nil
}

func (s *ExternalAuthenticationService) deleteResetPasswordSession(ctx context.Context, session, serviceName string) {
	if err := redis.HDelete[utils.ResetPasswordSession](
		ctx,
		utils.ResetPasswordSessionPrefix,
		session,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "vValkey delete", "service", serviceName, "error", err)
	}
}
