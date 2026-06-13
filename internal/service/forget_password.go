package service

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"neupaneanish.com.np/api/internal/enum"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
	"neupaneanish.com.np/api/internal/utils"
)

func (s *AuthService) ForgetPassword(
	ctx context.Context,
	req *authv1.ForgetPasswordRequest,
) (*authv1.ForgetPasswordResponse, error) {
	serviceName := "ForgetPassword"
	email := req.GetEmail()

	result, resultErr := s.cfg.RateLimiter.ForgetPassword.Allow(ctx, email)

	if limiterErr := LimiterCheck(ctx, &result, resultErr, serviceName, email, s.cfg.Logger); limiterErr != nil {
		return nil, limiterErr
	}

	session := rand.Text()

	response := &authv1.ForgetPasswordResponse{Response: &authv1.ForgetPasswordResponse_Session{Session: session}}

	if !s.cfg.Domain.ValidateEmail(email) {
		s.cfg.Logger.WarnContext(ctx, "invalid email", "email", email)
		return response, nil
	}

	params := &repository.UserByEmailParams{Email: email}

	row, rowErr := s.cfg.Repository.UserByEmail(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "email", email)
			return response, nil
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" database", "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	if row.Status == enum.UserStatusPending && row.EmailVerifiedAt == nil {
		emailErr := EmailVerification(
			ctx,
			serviceName,
			enum.MethodForgetPassword,
			session,
			row.ID.String(),
			string(row.Role),
			false,
			s.cfg.Client,
			s.cfg.Logger,
		)
		if emailErr != nil {
			return nil, emailErr
		}
		return &authv1.ForgetPasswordResponse{
			Response: &authv1.ForgetPasswordResponse_Verification{Verification: session},
		}, nil
	}

	switch row.Status {
	case enum.UserStatusActive:
		break
	case enum.UserStatusPending:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account pending", "email", email, "status", row.Status)
		return nil, errs.ErrAccountPending
	case enum.UserStatusLocked,
		enum.UserStatusDisabled,
		enum.UserStatusSuspended,
		enum.UserStatusArchived,
		enum.UserStatusDeleted:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account "+string(row.Status), "email", email, "status", row.Status)
		return response, nil
	}

	code, _, emailErr := GenerateEmailCode(ctx, s.cfg.Logger)
	if emailErr != nil {
		return nil, emailErr
	}

	data := &utils.ForgetPasswordSession{
		Key:    session,
		ExAt:   time.Now().Add(utils.SessionExpiry),
		UserID: row.ID.String(),
		Code:   code,
	}

	hSetErr := redis.HSet[utils.ForgetPasswordSession](ctx, utils.ForgetPasswordSessionPrefix, data, s.cfg.Client)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Access HSet", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	// TODO: Send code via email

	return response, nil
}
