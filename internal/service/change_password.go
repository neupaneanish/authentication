package service

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/jackc/pgx/v5"
	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ChangePassword(
	ctx context.Context,
	req *gatewayAuthenticationv1.ChangePasswordRequest,
) (*gatewayAuthenticationv1.ChangePasswordResponse, error) {
	serviceName := "ChangePassword"
	rawPassword := req.GetPassword().GetValue()

	userSession, userSessionErr := utils.GetUserSessionContext(ctx, serviceName, s.cfg.Logger)
	if userSessionErr != nil {
		return nil, userSessionErr
	}

	if workFlowErr := s.gatewayAuthenticationSecurityWorkflow(
		ctx,
		userSession.UserID.String(),
		serviceName,
		true,
	); workFlowErr != nil {
		return nil, workFlowErr
	}

	params := &repository.CredentialParams{UserID: userSession.UserID}
	row, rowErr := s.cfg.Repository.Credential(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(
				ctx,
				"No credentials found",
				"service",
				serviceName,
				"userID",
				userSession.UserID.String(),
			)
			// TODO: Delete Access and Refresh
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Postgres get", "service", serviceName, "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	if !utils.ComparePassword(row.Password, rawPassword) {
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Password",
			"service",
			serviceName,
			"userID",
			userSession.UserID.String(),
		)
		return nil, errs.ErrInvalidPassword
	}

	session := rand.Text()

	if cacheErr := s.gatewayAuthenticationSecurityWorkflowCache(
		ctx,
		userSession.UserID.String(),
		row.Email,
		session,
		serviceName,
		true,
	); cacheErr != nil {
		return nil, cacheErr
	}

	return &gatewayAuthenticationv1.ChangePasswordResponse{
		Session: session,
	}, nil
}
