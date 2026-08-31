package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) Role(
	ctx context.Context,
	_ *gatewayAuthenticationv1.RoleRequest,
) (*gatewayAuthenticationv1.RoleResponse, error) {
	serviceName := "Role"

	userSession := utils.UserSessionContext(ctx)

	params := &repository.RoleParams{ID: userSession.UserID}
	role, roleErr := s.cfg.Repository.Role(ctx, params)
	if roleErr != nil {
		if errors.Is(roleErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, "User not found", "service", serviceName)
			_ = LogoutAll(ctx, userSession.UserID.String(), serviceName, s.cfg.Client, s.cfg.Logger)
			return nil, errs.ErrUnauthenticated
		}
		s.cfg.Logger.ErrorContext(ctx, "PostgreSQL Role Query", "service", serviceName, "error", roleErr)
		return nil, errs.ErrInternalServer
	}

	return &gatewayAuthenticationv1.RoleResponse{Role: string(role)}, nil
}
