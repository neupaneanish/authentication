package service

import (
	"context"

	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

const (
	pageSize = 10
)

func (s *RootAuthenticationService) Users(
	ctx context.Context,
	_ *rootAuthenticationv1.UsersRequest,
) (*rootAuthenticationv1.UsersResponse, error) {
	serviceName := "Users"
	userSession := utils.UserSessionContext(ctx)

	params := &repository.UsersParams{PageSize: pageSize}

	users, err := s.cfg.Repository.Users(ctx, params)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Failed to fetch users", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}

	length := len(users)

	if length == 0 {
		s.cfg.Logger.WarnContext(ctx, "No users found in system", "service", serviceName)
		_ = LogoutAll(ctx, userSession.UserID.String(), serviceName, s.cfg.Client, s.cfg.Logger)
		return nil, errs.ErrUnauthenticated
	}

	userSummary := make([]*rootAuthenticationv1.UserSummary, length)
	for i, u := range users {
		userSummary[i] = &rootAuthenticationv1.UserSummary{
			Id:       u.ID.String(),
			Username: u.Username,
			Phone:    u.Phone,
		}
	}

	return &rootAuthenticationv1.UsersResponse{Users: userSummary}, nil
}
