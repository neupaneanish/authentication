package service

import (
	"context"
	"errors"
	"log/slog"
	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/valkey-io/valkey-go"

	rootAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/root/authentication/v1"

	"neupaneanish.com.np/authentication/internal/redpanda"

	authenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/common/authentication/v1"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) UpdateUsername(
	ctx context.Context,
	req *gatewayAuthenticationv1.UpdateUsernameRequest,
) (*gatewayAuthenticationv1.UpdateUsernameResponse, error) {
	serviceName := "GatewayUpdateUsername"
	userSession := utils.UserSessionContext(ctx)

	if err := updateUsername(
		ctx,
		req.GetUsername(),
		userSession,
		serviceName,
		userSession.UserID,
		s.cfg.Repository,
		s.cfg.Client,
		s.cfg.Redpanda,
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}
	return &gatewayAuthenticationv1.UpdateUsernameResponse{}, nil
}

func (s *RootAuthenticationService) UpdateUsername(
	ctx context.Context,
	req *rootAuthenticationv1.UpdateUsernameRequest,
) (*rootAuthenticationv1.UpdateUsernameResponse, error) {
	serviceName := "RootUpdateUsername"
	userSession := utils.UserSessionContext(ctx)

	userID, userIDErr := utils.ParsedUUID(ctx, req.GetId(), serviceName, s.cfg.Logger)
	if userIDErr != nil {
		return nil, userIDErr
	}

	if err := updateUsername(
		ctx,
		req.GetUsername(),
		userSession,
		serviceName,
		userID,
		s.cfg.Repository,
		s.cfg.Client,
		s.cfg.Redpanda,
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}
	return &rootAuthenticationv1.UpdateUsernameResponse{}, nil
}

func updateUsername(
	ctx context.Context,
	req *authenticationv1.Username,
	session *utils.UserSession,
	serviceName string,
	userID uuid.UUID,
	repo repository.Querier,
	client valkey.Client,
	rpClient *kgo.Client,
	logger *slog.Logger,
) error {
	username := req.GetValue()
	params := &repository.UpdateUsernameParams{
		Username:  username,
		UpdatedBy: session.UserID,
		ID:        userID,
		UpdatedAt: req.GetUpdatedAt().AsTime(),
	}

	affected, affectedErr := repo.UpdateUsername(ctx, params)
	if affectedErr != nil {
		if pgxErr, ok := errors.AsType[*pgconn.PgError](affectedErr); ok && pgxErr.Code == pgerrcode.UniqueViolation {
			logger.WarnContext(
				ctx,
				"Username collision: username already exists",
				"service",
				serviceName,
				"username",
				username,
			)
			return errs.ErrUsernameAlreadyExists
		}
		logger.ErrorContext(ctx, "Update username failed", "service", serviceName, "error", affectedErr)
		return errs.ErrInternalServer
	}

	if affected != 1 {
		logger.WarnContext(
			ctx,
			"User not found or concurrency check failed",
			"service",
			serviceName,
			"expected", 1,
			"actual", affected,
		)
		return errs.ErrConflict
	}

	LogoutAll(ctx, userID.String(), serviceName, client, logger)

	setUsername(ctx, userID.String(), username, serviceName, client, logger)

	redpanda.RootNotificationProduce(
		ctx,
		session,
		userID,
		utils.DatabaseTableUser,
		utils.DatabaseMethodUpdate,
		serviceName,
		client,
		rpClient,
		logger,
	)

	return nil
}
