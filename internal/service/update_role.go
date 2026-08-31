package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
)

//nolint:dupl // Clean handler pattern intentionally mirrors UpdateRole
func (s *RootAuthenticationService) UpdateRole(
	ctx context.Context,
	req *rootAuthenticationv1.UpdateRoleRequest,
) (*rootAuthenticationv1.UpdateRoleResponse, error) {
	serviceName := "UpdateRole"
	userSession, id, userSessionErr := s.updateUserSession(ctx, req.GetId(), serviceName)
	if userSessionErr != nil {
		return nil, userSessionErr
	}
	role := enum.UserRole(req.GetRole())
	if !role.Valid() {
		s.cfg.Logger.WarnContext(ctx, "Invalid Role", "service", serviceName)
		return nil, errs.ErrInvalidRole
	}

	params := &repository.UpdateRoleParams{
		Role:      role,
		UpdatedBy: userSession.UserID,
		ID:        id,
		UpdatedAt: req.GetUpdatedAt().AsTime(),
	}

	user, userErr := s.cfg.Repository.UpdateRole(ctx, params)
	if userErr != nil {
		if errors.Is(userErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, "User not found", "service", serviceName, "userID", id.String())
			_ = LogoutAll(ctx, id.String(), serviceName, s.cfg.Client, s.cfg.Logger)
			return nil, errs.ErrFailedPreconditionRole
		}
		s.cfg.Logger.ErrorContext(ctx, "Failed to update user role", "service", serviceName, "error", userErr)
		return nil, errs.ErrInternalServer
	}

	_ = LogoutAll(ctx, id.String(), serviceName, s.cfg.Client, s.cfg.Logger)

	return &rootAuthenticationv1.UpdateRoleResponse{
		Id:        user.ID.String(),
		Role:      string(user.Role),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
		UpdatedBy: user.UpdatedBy.String(),
	}, nil
}
