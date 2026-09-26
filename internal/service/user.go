package service

import (
	"context"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/utils"

	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
)

func (s *RootAuthenticationService) User(
	ctx context.Context,
	req *rootAuthenticationv1.UserRequest,
) (*rootAuthenticationv1.UserResponse, error) {
	serviceName := "User"
	userSession := utils.UserSessionContext(ctx)

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

	user, userErr := s.cfg.Repository.User(ctx, params)
	if userErr != nil {
		if errors.Is(userErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, "User not found", "service", serviceName, "userID", userID.String())
			LogoutAll(ctx, req.GetId(), serviceName, s.cfg.Client, s.cfg.Logger)
			return nil, errs.ErrNotFound
		}
		s.cfg.Logger.ErrorContext(ctx, "Failed to fetch user", "service", serviceName, "error", userErr)
		return nil, errs.ErrInternalServer
	}

	createdByUsername, updatedByUsername, usernameErr := utils.GetUsernames(
		ctx,
		user.CreatedBy,
		user.UpdatedBy,
		userSession,
		s.cfg.Client,
		s.cfg.Logger,
	)
	if usernameErr != nil {
		return nil, usernameErr
	}

	return &rootAuthenticationv1.UserResponse{
		Id:                    user.ID.String(),
		Email:                 user.Email,
		Username:              user.Username,
		Phone:                 user.Phone,
		Role:                  string(user.Role),
		Status:                string(user.Status),
		EmailVerified:         user.EmailVerified,
		EmailVerifiedAt:       utils.TimestamppbValue(user.EmailVerifiedAt),
		PhoneVerified:         user.PhoneVerified,
		PhoneVerifiedAt:       utils.TimestamppbValue(user.PhoneVerifiedAt),
		TwoFactor:             user.TwoFactor,
		LastPasswordUpdatedAt: timestamppb.New(user.LastPasswordUpdatedAt),
		CreatedAt:             timestamppb.New(user.CreatedAt),
		CreatedBy:             user.CreatedBy.String(),
		UpdatedAt:             timestamppb.New(user.UpdatedAt),
		UpdatedBy:             user.UpdatedBy.String(),
		CreatedByUsername:     createdByUsername,
		UpdatedByUsername:     updatedByUsername,
	}, nil
}
