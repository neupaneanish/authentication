package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) Profile(
	ctx context.Context,
	_ *gatewayAuthenticationv1.ProfileRequest,
) (*gatewayAuthenticationv1.ProfileResponse, error) {
	serviceName := "Profile"
	userSession := utils.UserSessionContext(ctx)

	params := &repository.UserParams{ID: userSession.UserID}
	user, userErr := s.cfg.Repository.User(ctx, params)
	if userErr != nil {
		if errors.Is(userErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, "User not found", "service", serviceName)
			_ = s.logoutAll(ctx, userSession.UserID.String(), serviceName)
			return nil, errs.ErrUnauthenticated
		}
		s.cfg.Logger.ErrorContext(ctx, "PostgreSQL User Query", "service", serviceName, "error", userErr)
		return nil, errs.ErrInternalServer
	}

	return &gatewayAuthenticationv1.ProfileResponse{
		Email:                 user.Email,
		Username:              user.Username,
		Phone:                 user.Phone,
		Status:                string(user.Status),
		TwoFactorEnabled:      user.TwoFactor,
		LastPasswordChangedAt: timestamppb.New(user.LastPasswordUpdatedAt),
		AccountCreatedAt:      timestamppb.New(user.CreatedAt),
	}, nil
}
