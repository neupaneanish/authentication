package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"neupaneanish.com.np/api/internal/enum"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
)

func (s *AuthService) ForgetPassword(
	ctx context.Context,
	req *authv1.ForgetPasswordRequest,
) (*authv1.ForgetPasswordResponse, error) {
	serviceName := "ForgetPassword"
	email := req.GetEmail()

	result, resultErr := s.cfg.RateLimiter.ForgetPassword.Allow(ctx, email)

	if limiterErr := limiterCheck(ctx, &result, resultErr, serviceName, s.cfg.Logger, email); limiterErr != nil {
		return nil, limiterErr
	}

	params := &repository.UserByEmailParams{Email: email}
	repo := repository.New(s.cfg.Pool)

	session := rand.Text()

	response := &authv1.ForgetPasswordResponse{Session: session}

	row, rowErr := repo.UserByEmail(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "email", email)
			return response, nil
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" database", "error", rowErr)
		return nil, errs.ErrInternalServer
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

	codeByte := make([]byte, emailCodeBytes)
	if _, err := rand.Read(codeByte); err != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Email code", "error", err)
		return nil, err
	}

	code := fmt.Sprintf("%X", codeByte)
	_ = fmt.Sprintf("%s-%s", code[0:4], code[4:8])

	data := &ForgetPasswordSession{
		Key:    session,
		ExAt:   time.Now().Add(SessionExpiry),
		UserID: row.ID.String(),
		Code:   code,
	}

	hSetErr := redis.HSet[ForgetPasswordSession](ctx, ForgetPasswordSessionPrefix, data, s.cfg.Client)
	if hSetErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Access HSet", "error", hSetErr)
		return nil, errs.ErrInternalServer
	}

	// TODO: Send code via email

	return response, nil
}
