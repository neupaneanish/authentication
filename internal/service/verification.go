package service

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/valkey-io/valkey-go/om"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/utils"
)

func (s *AuthService) Verification(
	ctx context.Context,
	req *authv1.VerificationRequest,
) (*authv1.VerificationResponse, error) {
	serviceName := "Verification"
	code := req.GetCode()
	session := req.GetSession()

	result, resultErr := s.cfg.RateLimiter.Verification.Allow(ctx, session)
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

	fpSession, fpSessionErr := redis.HGet[utils.ForgetPasswordSession](
		ctx,
		utils.ForgetPasswordSessionPrefix,
		session,
		s.cfg.Client,
	)
	if fpSessionErr != nil {
		if om.IsRecordNotFound(fpSessionErr) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "session", session)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey get", "error", fpSessionErr)
		return nil, errs.ErrInternalServer
	}

	resultUserID, resultUserIDErr := s.cfg.RateLimiter.VerificationUserID.Allow(ctx, fpSession.UserID)
	if userIDLimiterErr := LimiterCheck(
		ctx,
		&resultUserID,
		resultUserIDErr,
		serviceName,
		fpSession.UserID,
		s.cfg.Logger,
	); userIDLimiterErr != nil {
		return nil, userIDLimiterErr
	}

	if fpSession.Code != code {
		s.cfg.Logger.WarnContext(ctx, serviceName+" invalid code", "userID", fpSession.UserID)
		return nil, errs.ErrInvalidCode
	}

	newSession := rand.Text()
	resetSession := &utils.ResetPasswordSession{
		Key:    newSession,
		ExAt:   time.Now().Add(utils.SessionExpiry),
		UserID: fpSession.UserID,
		Email:  fpSession.Email,
	}

	hSetErr := redis.HSet[utils.ResetPasswordSession](ctx, utils.ResetPasswordSessionPrefix, resetSession, s.cfg.Client)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" new session set", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	hDeleteErr := redis.HDelete[utils.ForgetPasswordSession](
		ctx,
		utils.ForgetPasswordSessionPrefix,
		session,
		s.cfg.Client,
	)
	if hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" session delete", "error", hDeleteErr)
		return nil, errs.ErrInternalServer
	}

	return &authv1.VerificationResponse{Session: newSession}, nil
}
