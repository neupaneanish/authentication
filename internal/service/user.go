package service

import (
	"context"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
)

func (s *RootAuthenticationService) User(
	ctx context.Context,
	req *rootAuthenticationv1.UserRequest,
) (*rootAuthenticationv1.UserResponse, error) {
	serviceName := "User"

	userID, userIDErr := uuid.Parse(req.GetId())
	if userIDErr != nil {
		s.cfg.Logger.ErrorContext(
			ctx,
			"Invalid User ID",
			"service",
			serviceName,
			"userID",
			req.GetId(),
			"error",
			userIDErr,
		)
		return nil, errs.ErrNotFound
	}
	params := &repository.UserParams{ID: userID}

	user, err := s.cfg.Repository.User(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, "User not found", "service", serviceName, "userID", userID.String())
			_ = LogoutAll(ctx, userID.String(), serviceName, s.cfg.Client, s.cfg.Logger)
			return nil, errs.ErrNotFound
		}
		s.cfg.Logger.ErrorContext(ctx, "Failed to fetch user", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}
	return &rootAuthenticationv1.UserResponse{
		Id:                    user.ID.String(),
		Email:                 user.Email,
		Username:              user.Username,
		Phone:                 user.Phone,
		Role:                  string(user.Role),
		Status:                string(user.Status),
		EmailVerified:         user.EmailVerified,
		TwoFactor:             user.TwoFactor,
		LastPasswordUpdatedAt: timestamppb.New(user.LastPasswordUpdatedAt),
		CreatedAt:             timestamppb.New(user.CreatedAt),
		CreatedBy:             user.CreatedBy.String(),
		UpdatedAt:             timestamppb.New(user.UpdatedAt),
		UpdatedBy:             user.UpdatedBy.String(),
	}, nil
}
