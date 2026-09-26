package service

import (
	"context"
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/valkey-io/valkey-go/om"

	"neupaneanish.com.np/authentication/internal/redpanda"

	"neupaneanish.com.np/authentication/internal/repository"

	"neupaneanish.com.np/authentication/internal/errs"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *GatewayAuthenticationService) ChangeEmail(
	ctx context.Context,
	req *gatewayAuthenticationv1.ChangeEmailRequest,
) (*gatewayAuthenticationv1.ChangeEmailResponse, error) {
	serviceName := "ChangeEmail"
	userSession := utils.UserSessionContext(ctx)
	email := req.GetEmail()

	result, resultErr := s.cfg.RateLimiter.ChangeEmailWorkFlow.Allow(ctx, userSession.UserID.String())
	if err := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		userSession.UserID.String(),
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}

	data, dataErr := redis.HGet[utils.ChangeEmailSession](
		ctx,
		utils.ChangeEmailSessionPrefix,
		userSession.UserID.String(),
		s.cfg.Client,
	)
	if dataErr != nil {
		if om.IsRecordNotFound(dataErr) {
			s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, "Valkey get", "service", serviceName, "error", dataErr)
		return nil, errs.ErrInternalServer
	}

	if data.Session != req.GetSession() {
		s.cfg.Logger.WarnContext(ctx, "session expired", "service", serviceName)
		s.deleteChangeEmailSession(ctx, data.Key, serviceName)
		return nil, errs.ErrSessionExpired
	}

	if err := s.cfg.EmailVerifier.Validate(email); err != nil {
		s.cfg.Logger.ErrorContext(
			ctx, "Invalid email",
			"service", serviceName,
			"email", email,
			"error", err,
		)
		return nil, errs.ErrInvalidEmail
	}

	params := &repository.UpdateEmailParams{
		Email:     email,
		UpdatedBy: userSession.UserID,
		ID:        userSession.UserID,
	}

	_, affectedErr := s.cfg.Repository.UpdateEmail(ctx, params)
	if affectedErr != nil {
		if pgxErr, ok := errors.AsType[*pgconn.PgError](affectedErr); ok && pgxErr.Code == pgerrcode.UniqueViolation {
			s.cfg.Logger.WarnContext(
				ctx,
				"Email collision: email already exists",
				"service", serviceName,
				"email", email,
			)
			return nil, errs.ErrEmailAlreadyExists
		}
		s.cfg.Logger.ErrorContext(ctx, "Update email failed", "service", serviceName, "error", affectedErr)
		return nil, errs.ErrInternalServer
	}
	s.deleteChangeEmailSession(ctx, data.Key, serviceName)

	LogoutAll(ctx, userSession.UserID.String(), serviceName, s.cfg.Client, s.cfg.Logger)

	redpanda.SecurityEmailProduce(
		ctx,
		userSession.UserID,
		email,
		utils.EmailTemplateSuccessChangeEmail,
		serviceName,
		s.cfg.Redpanda,
		s.cfg.Logger,
	)

	redpanda.RootNotificationProduce(
		ctx,
		userSession.UserID,
		userSession.UserID,
		userSession.Username,
		utils.DatabaseTableUser,
		utils.DatabaseMethodUpdate,
		serviceName,
		s.cfg.Redpanda,
		s.cfg.Logger,
	)

	return &gatewayAuthenticationv1.ChangeEmailResponse{}, nil
}

func (s *GatewayAuthenticationService) deleteChangeEmailSession(ctx context.Context, key, serviceName string) {
	if err := redis.HDelete[utils.ChangeEmailSession](
		ctx,
		utils.ChangeEmailSessionPrefix,
		key,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Valkey delete setup session", "service", serviceName, "error", err)
	}
}
