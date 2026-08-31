package service

import (
	"context"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

//nolint:dupl // Clean handler pattern intentionally mirrors UpdateStatus
func (s *RootAuthenticationService) UpdateStatus(
	ctx context.Context,
	req *rootAuthenticationv1.UpdateStatusRequest,
) (*rootAuthenticationv1.UpdateStatusResponse, error) {
	serviceName := "UpdateStatus"
	userSession, id, userSessionErr := s.updateUserSession(ctx, req.GetId(), serviceName)
	if userSessionErr != nil {
		return nil, userSessionErr
	}

	status := enum.UserStatus(req.GetStatus())
	if !status.Valid() {
		s.cfg.Logger.WarnContext(ctx, "Invalid Status", "service", serviceName)
		return nil, errs.ErrInvalidStatus
	}

	params := &repository.UpdateStatusParams{
		Status:    status,
		UpdatedBy: userSession.UserID,
		ID:        id,
		UpdatedAt: req.GetUpdatedAt().AsTime(),
	}

	user, userErr := s.cfg.Repository.UpdateStatus(ctx, params)
	if userErr != nil {
		if errors.Is(userErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, "User not found", "service", serviceName, "userID", id.String())
			_ = LogoutAll(ctx, id.String(), serviceName, s.cfg.Client, s.cfg.Logger)
			return nil, errs.ErrFailedPreconditionStatus
		}
		s.cfg.Logger.ErrorContext(ctx, "Failed to update user status", "service", serviceName, "error", userErr)
		return nil, errs.ErrInternalServer
	}

	_ = LogoutAll(ctx, id.String(), serviceName, s.cfg.Client, s.cfg.Logger)

	return &rootAuthenticationv1.UpdateStatusResponse{
		Id:        user.ID.String(),
		Status:    string(user.Status),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
		UpdatedBy: user.UpdatedBy.String(),
	}, nil
}

func (s *RootAuthenticationService) updateUserSession(
	ctx context.Context,
	userID, serviceName string,
) (*utils.UserSession, uuid.UUID, error) {
	userSession := utils.UserSessionContext(ctx)
	id, idErr := uuid.Parse(userID)
	if idErr != nil {
		s.cfg.Logger.ErrorContext(
			ctx,
			"Invalid User ID",
			"service",
			serviceName,
			"userID",
			userID,
			"error",
			idErr,
		)
		return nil, uuid.Nil(), errs.ErrNotFound
	}

	if id == userSession.UserID {
		s.cfg.Logger.WarnContext(ctx, "Attempted self update", "service", serviceName)
		return nil, uuid.Nil(), errs.ErrSelfUpdate
	}

	return userSession, id, nil
}
