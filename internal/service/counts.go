package service

import (
	"context"

	"neupaneanish.com.np/authentication/internal/errs"
	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *RootAuthenticationService) Counts(
	ctx context.Context,
	_ *rootAuthenticationv1.CountsRequest,
) (*rootAuthenticationv1.CountsResponse, error) {
	serviceName := "Counts"
	userSession := utils.UserSessionContext(ctx)

	params := &repository.CountsParams{ID: userSession.UserID}

	count, err := s.cfg.Repository.Counts(ctx, params)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Counts query failed", "service", serviceName, "error", err)
		return nil, errs.ErrInternalServer
	}

	return &rootAuthenticationv1.CountsResponse{Users: count}, nil
}
