package service

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
	"neupaneanish.com.np/api/internal/enum"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
	"neupaneanish.com.np/api/internal/utils"
)

func (s *AuthService) Login(
	ctx context.Context,
	req *authv1.LoginRequest,
) (*authv1.LoginResponse, error) {
	serviceName := "Login"
	email := req.GetEmail()

	result, resultErr := s.cfg.RateLimiter.Login.Allow(ctx, email)
	if limiterErr := s.limiterCheck(ctx, &result, resultErr, serviceName, email); limiterErr != nil {
		return nil, limiterErr
	}

	params := &repository.LoginParams{Email: email}

	row, rowErr := s.cfg.Repository.Login(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "email", email)
			return nil, errs.ErrInvalidCredentials
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" database", "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	switch row.Status {
	case enum.UserStatusActive:
		break
	case enum.UserStatusPending:
		s.cfg.Logger.WarnContext(ctx, serviceName+" account pending", "email", email)
		return nil, errs.ErrAccountPending
	case enum.UserStatusLocked, enum.UserStatusDisabled, enum.UserStatusSuspended:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account "+string(row.Status), "email", email, "status", row.Status)
		return nil, errs.ErrAccountRestricted
	case enum.UserStatusArchived, enum.UserStatusDeleted:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account "+string(row.Status), "email", email, "status", row.Status)
		return nil, errs.ErrInvalidCredentials
	}

	if !utils.ComparePassword(row.Password, req.GetPassword().GetValue()) {
		s.cfg.Logger.WarnContext(ctx, serviceName+" invalid password", "email", email)
		return nil, errs.ErrInvalidCredentials
	}

	session := rand.Text()

	if row.TwoFactor {
		tfSession := &LoginTwoFactorSession{
			Key:    session,
			ExAt:   time.Now().Add(SessionExpiry),
			UserID: row.ID.String(),
			Role:   string(row.Role),
		}
		hSetErr := redis.HSet[LoginTwoFactorSession](ctx, LoginTwoFactorSessionPrefix, tfSession, s.cfg.Client)
		if hSetErr != nil {
			s.cfg.Logger.ErrorContext(ctx, serviceName+" Valkey Two Factor HSet", "error", hSetErr)
			return nil, errs.ErrInternalServer
		}
		return &authv1.LoginResponse{
			Response: &authv1.LoginResponse_Session{Session: session},
		}, nil
	}

	jwt, jwtErr := s.login(ctx, row.ID.String(), string(row.Role), serviceName)
	if jwtErr != nil {
		return nil, jwtErr
	}

	return &authv1.LoginResponse{
		Response: &authv1.LoginResponse_Token{
			Token: &authv1.Token{
				Access:   jwt.Access,
				Refresh:  jwt.Refresh,
				ExpireAt: timestamppb.New(jwt.ExpiryAt),
			},
		},
	}, nil
}
